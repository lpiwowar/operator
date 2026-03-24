/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ReconcilePostgresResources reconciles Postgres prerequisite resources (Phase 1):
// ConfigMap, Bootstrap Secret, Password Secret, and Network Policy.
func ReconcilePostgresResources(r Reconciler, ctx context.Context, cfg *LCoreConfig) error {
	logger := r.GetLogger()
	logger.Info("reconciling Postgres resources")

	tasks := []ReconcileTask{
		{Name: "PostgresConfigMap", Task: reconcilePostgresConfigMap},
		{Name: "PostgresBootstrapSecret", Task: reconcilePostgresBootstrapSecret},
		{Name: "PostgresSecret", Task: reconcilePostgresSecret},
		{Name: "PostgresNetworkPolicy", Task: reconcilePostgresNetworkPolicy},
	}

	var firstErr error
	for _, t := range tasks {
		if err := t.Task(r, ctx, cfg); err != nil {
			logger.Error(err, "failed to reconcile Postgres resource", "task", t.Name)
			if firstErr == nil {
				firstErr = fmt.Errorf("task %s: %w", t.Name, err)
			}
		}
	}

	if firstErr != nil {
		return firstErr
	}

	logger.Info("Postgres resources reconciled")
	return nil
}

// ReconcilePostgresDeployment reconciles the Postgres Deployment and Service (Phase 2).
func ReconcilePostgresDeployment(r Reconciler, ctx context.Context, cfg *LCoreConfig) error {
	logger := r.GetLogger()
	logger.Info("reconciling Postgres deployment")

	tasks := []ReconcileTask{
		{Name: "PostgresDeployment", Task: reconcilePostgresDeploymentTask},
		{Name: "PostgresService", Task: reconcilePostgresServiceTask},
	}

	for _, t := range tasks {
		if err := t.Task(r, ctx, cfg); err != nil {
			return fmt.Errorf("task %s: %w", t.Name, err)
		}
	}

	logger.Info("Postgres deployment reconciled")
	return nil
}

func reconcilePostgresConfigMap(r Reconciler, ctx context.Context, _ *LCoreConfig) error {
	desired, err := GeneratePostgresConfigMap(r)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGeneratePostgresConfigMap, err)
	}

	existing := &corev1.ConfigMap{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil && errors.IsNotFound(err) {
		r.GetLogger().Info("creating Postgres ConfigMap", "name", desired.Name)
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("%s: %w", ErrCreatePostgresConfigMap, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetPostgresConfigMap, err)
	}

	r.GetLogger().Info("Postgres ConfigMap already exists, skipping", "name", desired.Name)
	return nil
}

func reconcilePostgresBootstrapSecret(r Reconciler, ctx context.Context, _ *LCoreConfig) error {
	desired, err := GeneratePostgresBootstrapSecret(r)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGeneratePostgresBootstrapSecret, err)
	}

	existing := &corev1.Secret{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil && errors.IsNotFound(err) {
		r.GetLogger().Info("creating Postgres bootstrap secret", "name", desired.Name)
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("%s: %w", ErrCreatePostgresBootstrapSecret, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetPostgresBootstrapSecret, err)
	}

	r.GetLogger().Info("Postgres bootstrap secret already exists, skipping", "name", desired.Name)
	return nil
}

func reconcilePostgresSecret(r Reconciler, ctx context.Context, _ *LCoreConfig) error {
	desired, err := GeneratePostgresSecret(r)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGeneratePostgresSecret, err)
	}

	existing := &corev1.Secret{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil && errors.IsNotFound(err) {
		// Delete any old postgres secrets before creating a new one
		if err := deleteOldPostgresSecrets(r, ctx); err != nil {
			return err
		}
		r.GetLogger().Info("creating Postgres secret", "name", desired.Name)
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("%s: %w", ErrCreatePostgresSecret, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetPostgresSecret, err)
	}

	// Secret already exists — don't regenerate password
	r.GetLogger().Info("Postgres secret already exists, skipping", "name", existing.Name)
	return nil
}

func deleteOldPostgresSecrets(r Reconciler, ctx context.Context) error {
	labelSelector := labels.Set{"app.kubernetes.io/name": "lightspeed-service-postgres"}.AsSelector()
	matchingLabels := client.MatchingLabelsSelector{Selector: labelSelector}
	deleteOptions := &client.DeleteAllOfOptions{
		ListOptions: client.ListOptions{
			Namespace:     r.GetNamespace(),
			LabelSelector: matchingLabels,
		},
	}
	if err := r.DeleteAllOf(ctx, &corev1.Secret{}, deleteOptions); err != nil {
		return fmt.Errorf("failed to delete old Postgres secrets: %w", err)
	}
	return nil
}

func reconcilePostgresNetworkPolicy(r Reconciler, ctx context.Context, _ *LCoreConfig) error {
	desired, err := GeneratePostgresNetworkPolicy(r)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGeneratePostgresNetworkPolicy, err)
	}

	existing := &networkingv1.NetworkPolicy{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil && errors.IsNotFound(err) {
		r.GetLogger().Info("creating Postgres NetworkPolicy", "name", desired.Name)
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("%s: %w", ErrCreatePostgresNetworkPolicy, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetPostgresNetworkPolicy, err)
	}

	if !NetworkPolicyEqual(existing, desired) {
		r.GetLogger().Info("updating Postgres NetworkPolicy", "name", desired.Name)
		existing.Spec = desired.Spec
		if err := r.Update(ctx, existing); err != nil {
			return fmt.Errorf("%s: %w", ErrUpdatePostgresNetworkPolicy, err)
		}
	}

	return nil
}

func reconcilePostgresDeploymentTask(r Reconciler, ctx context.Context, _ *LCoreConfig) error {
	desired, err := GeneratePostgresDeployment(r, ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGeneratePostgresDeployment, err)
	}

	existing := &appsv1.Deployment{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil && errors.IsNotFound(err) {
		r.GetLogger().Info("creating Postgres Deployment", "name", desired.Name)
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("%s: %w", ErrCreatePostgresDeployment, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetPostgresDeployment, err)
	}

	if err := UpdatePostgresDeployment(r, ctx, existing, desired); err != nil {
		return fmt.Errorf("%s: %w", ErrUpdatePostgresDeployment, err)
	}

	return nil
}

func reconcilePostgresServiceTask(r Reconciler, ctx context.Context, _ *LCoreConfig) error {
	desired, err := GeneratePostgresService(r)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGeneratePostgresService, err)
	}

	existing := &corev1.Service{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil && errors.IsNotFound(err) {
		r.GetLogger().Info("creating Postgres Service", "name", desired.Name)
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("%s: %w", ErrCreatePostgresService, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetPostgresService, err)
	}

	r.GetLogger().Info("Postgres Service already exists, skipping", "name", desired.Name)
	return nil
}

// RestartPostgres triggers a rolling restart of the Postgres deployment
// by updating the force-reload annotation on the pod template.
func RestartPostgres(r Reconciler, ctx context.Context, deployments ...*appsv1.Deployment) error {
	var deployment *appsv1.Deployment

	if len(deployments) > 0 && deployments[0] != nil {
		deployment = deployments[0]
	} else {
		deployment = &appsv1.Deployment{}
		err := r.Get(ctx, client.ObjectKey{Name: PostgresDeploymentName, Namespace: r.GetNamespace()}, deployment)
		if err != nil {
			if errors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("failed to get Postgres deployment for restart: %w", err)
		}
	}

	if deployment.Spec.Template.ObjectMeta.Annotations == nil {
		deployment.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
	}

	deployment.Spec.Template.ObjectMeta.Annotations[ForceReloadAnnotationKey] = fmt.Sprintf("%d", time.Now().UnixNano())

	if err := r.Update(ctx, deployment); err != nil {
		return fmt.Errorf("failed to restart Postgres deployment: %w", err)
	}

	r.GetLogger().Info("Triggered Postgres deployment restart")
	return nil
}
