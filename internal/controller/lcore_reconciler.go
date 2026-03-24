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

	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ReconcileLCoreResources reconciles Phase 1 resources: service accounts, roles,
// config maps, secrets, and network policies. Uses a continue-on-error pattern
// so that all tasks are attempted even if some fail.
func ReconcileLCoreResources(r Reconciler, ctx context.Context, cfg *LCoreConfig) error {
	logger := r.GetLogger()

	tasks := []ReconcileTask{
		{Name: "ServiceAccount", Task: reconcileServiceAccount},
		{Name: "SARRole", Task: reconcileSARRole},
		{Name: "SARRoleBinding", Task: reconcileSARRoleBinding},
		{Name: "LlamaStackConfigMap", Task: reconcileLlamaStackConfigMap},
		{Name: "LcoreConfigMap", Task: reconcileLcoreConfigMap},
		{Name: "ExporterConfigMap", Task: reconcileExporterConfigMap},
		{Name: "OLSAdditionalCAConfigMap", Task: reconcileOLSAdditionalCAConfigMap},
		{Name: "ProxyCAConfigMap", Task: reconcileProxyCAConfigMap},
		{Name: "MetricsReaderSecret", Task: reconcileMetricsReaderSecret},
		{Name: "NetworkPolicy", Task: reconcileNetworkPolicy},
	}

	var firstErr error
	for _, t := range tasks {
		if err := t.Task(r, ctx, cfg); err != nil {
			logger.Error(err, "failed to reconcile resource", "task", t.Name)
			if firstErr == nil {
				firstErr = fmt.Errorf("task %s: %w", t.Name, err)
			}
		}
	}

	return firstErr
}

// ReconcileLCoreDeployment reconciles Phase 2 resources: deployment, service,
// TLS secret, service monitor, and prometheus rule. Uses a fail-fast pattern
// where the first error stops execution.
func ReconcileLCoreDeployment(r Reconciler, ctx context.Context, cfg *LCoreConfig) error {
	tasks := []ReconcileTask{
		{Name: "Deployment", Task: reconcileDeployment},
		{Name: "Service", Task: reconcileService},
		{Name: "TLSSecret", Task: reconcileTLSSecret},
		{Name: "ServiceMonitor", Task: reconcileServiceMonitor},
		{Name: "PrometheusRule", Task: reconcilePrometheusRule},
	}

	for _, t := range tasks {
		if err := t.Task(r, ctx, cfg); err != nil {
			return fmt.Errorf("task %s: %w", t.Name, err)
		}
	}

	return nil
}

// reconcileServiceAccount ensures the OLS app server service account exists.
func reconcileServiceAccount(r Reconciler, ctx context.Context, cfg *LCoreConfig) error {
	logger := r.GetLogger()

	sa, err := GenerateServiceAccount(r, cfg)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGenerateAPIServiceAccount, err)
	}

	existing := &corev1.ServiceAccount{}
	err = r.Get(ctx, client.ObjectKeyFromObject(sa), existing)
	if err != nil && errors.IsNotFound(err) {
		logger.Info("creating ServiceAccount", "name", sa.Name)
		if err := r.Create(ctx, sa); err != nil {
			return fmt.Errorf("%s: %w", ErrCreateAPIServiceAccount, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetAPIServiceAccount, err)
	}

	logger.Info("ServiceAccount already exists, skipping", "name", sa.Name)
	return nil
}

// reconcileSARRole ensures the SAR cluster role exists.
func reconcileSARRole(r Reconciler, ctx context.Context, cfg *LCoreConfig) error {
	logger := r.GetLogger()

	role, err := GenerateSARClusterRole(r, cfg)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGenerateSARClusterRole, err)
	}

	existing := &rbacv1.ClusterRole{}
	err = r.Get(ctx, client.ObjectKeyFromObject(role), existing)
	if err != nil && errors.IsNotFound(err) {
		logger.Info("creating SAR ClusterRole", "name", role.Name)
		if err := r.Create(ctx, role); err != nil {
			return fmt.Errorf("%s: %w", ErrCreateSARClusterRole, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetSARClusterRole, err)
	}

	logger.Info("SAR ClusterRole already exists, skipping", "name", role.Name)
	return nil
}

// reconcileSARRoleBinding ensures the SAR cluster role binding exists.
func reconcileSARRoleBinding(r Reconciler, ctx context.Context, cfg *LCoreConfig) error {
	logger := r.GetLogger()

	rb, err := generateSARClusterRoleBinding(r, cfg)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGenerateSARClusterRoleBinding, err)
	}

	existing := &rbacv1.ClusterRoleBinding{}
	err = r.Get(ctx, client.ObjectKeyFromObject(rb), existing)
	if err != nil && errors.IsNotFound(err) {
		logger.Info("creating SAR ClusterRoleBinding", "name", rb.Name)
		if err := r.Create(ctx, rb); err != nil {
			return fmt.Errorf("%s: %w", ErrCreateSARClusterRoleBinding, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetSARClusterRoleBinding, err)
	}

	logger.Info("SAR ClusterRoleBinding already exists, skipping", "name", rb.Name)
	return nil
}

// reconcileLlamaStackConfigMap ensures the Llama Stack config map exists and is up to date.
func reconcileLlamaStackConfigMap(r Reconciler, ctx context.Context, cfg *LCoreConfig) error {
	logger := r.GetLogger()

	desired, err := GenerateLlamaStackConfigMap(r, ctx, cfg)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGenerateLlamaStackConfigMap, err)
	}

	existing := &corev1.ConfigMap{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil && errors.IsNotFound(err) {
		logger.Info("creating Llama Stack ConfigMap", "name", desired.Name)
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("%s: %w", ErrCreateLlamaStackConfigMap, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetLlamaStackConfigMap, err)
	}

	if !ConfigMapEqual(existing, desired) {
		logger.Info("updating Llama Stack ConfigMap", "name", desired.Name)
		existing.Data = desired.Data
		existing.BinaryData = desired.BinaryData
		if err := r.Update(ctx, existing); err != nil {
			return fmt.Errorf("%s: %w", ErrUpdateLlamaStackConfigMap, err)
		}
	}

	return nil
}

// reconcileLcoreConfigMap ensures the LCore config map exists and is up to date.
func reconcileLcoreConfigMap(r Reconciler, ctx context.Context, cfg *LCoreConfig) error {
	logger := r.GetLogger()

	desired, err := GenerateLcoreConfigMap(r, ctx, cfg)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGenerateAPIConfigmap, err)
	}

	existing := &corev1.ConfigMap{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil && errors.IsNotFound(err) {
		logger.Info("creating LCore ConfigMap", "name", desired.Name)
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("%s: %w", ErrCreateAPIConfigmap, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetAPIConfigmap, err)
	}

	if !ConfigMapEqual(existing, desired) {
		logger.Info("updating LCore ConfigMap", "name", desired.Name)
		existing.Data = desired.Data
		existing.BinaryData = desired.BinaryData
		if err := r.Update(ctx, existing); err != nil {
			return fmt.Errorf("%s: %w", ErrUpdateAPIConfigmap, err)
		}
	}

	return nil
}

// reconcileExporterConfigMap manages the data exporter config map based on whether
// data collection is enabled. Data collection is disabled when both feedback and
// transcripts are disabled.
func reconcileExporterConfigMap(r Reconciler, ctx context.Context, cfg *LCoreConfig) error {
	logger := r.GetLogger()

	dataCollectorEnabled := !cfg.FeedbackDisabled || !cfg.TranscriptsDisabled

	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, client.ObjectKey{
		Name:      ExporterConfigCmName,
		Namespace: r.GetNamespace(),
	}, existing)

	if !dataCollectorEnabled {
		// Data collection disabled: delete the config map if it exists
		if err == nil {
			logger.Info("data collection disabled, deleting exporter ConfigMap", "name", ExporterConfigCmName)
			if err := r.Delete(ctx, existing); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete exporter configmap: %w", err)
			}
		} else if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get exporter configmap: %w", err)
		}
		return nil
	}

	// Data collection enabled: create or update the config map
	desired, genErr := generateExporterConfigMap(r, cfg)
	if genErr != nil {
		return fmt.Errorf("failed to generate exporter configmap: %w", genErr)
	}

	if err != nil && errors.IsNotFound(err) {
		logger.Info("creating exporter ConfigMap", "name", desired.Name)
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("failed to create exporter configmap: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get exporter configmap: %w", err)
	}

	if !ConfigMapEqual(existing, desired) {
		logger.Info("updating exporter ConfigMap", "name", desired.Name)
		existing.Data = desired.Data
		existing.BinaryData = desired.BinaryData
		if err := r.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update exporter configmap: %w", err)
		}
	}

	return nil
}

// reconcileOLSAdditionalCAConfigMap verifies that the additional CA config map
// exists if one is specified in the configuration.
func reconcileOLSAdditionalCAConfigMap(r Reconciler, ctx context.Context, cfg *LCoreConfig) error {
	logger := r.GetLogger()

	if cfg.AdditionalCAConfigMapName == "" {
		logger.Info("no additional CA configmap configured, skipping")
		return nil
	}

	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, client.ObjectKey{
		Name:      cfg.AdditionalCAConfigMapName,
		Namespace: r.GetNamespace(),
	}, existing)
	if err != nil {
		return fmt.Errorf("%s %q: %w", ErrGetAdditionalCACM, cfg.AdditionalCAConfigMapName, err)
	}

	logger.Info("additional CA configmap found", "name", cfg.AdditionalCAConfigMapName)
	return nil
}

// reconcileProxyCAConfigMap is a no-op for the minimal mapping (no proxy config).
func reconcileProxyCAConfigMap(r Reconciler, _ context.Context, _ *LCoreConfig) error {
	logger := r.GetLogger()
	logger.Info("proxy CA configmap reconciliation skipped (no proxy config in minimal mapping)")
	return nil
}

// reconcileMetricsReaderSecret ensures the metrics reader token secret exists
// and has the correct type and annotations.
func reconcileMetricsReaderSecret(r Reconciler, ctx context.Context, cfg *LCoreConfig) error {
	logger := r.GetLogger()

	desired, err := GenerateMetricsReaderSecret(r, cfg)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGenerateMetricsReaderSecret, err)
	}

	existing := &corev1.Secret{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil && errors.IsNotFound(err) {
		logger.Info("creating metrics reader secret", "name", desired.Name)
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("%s: %w", ErrCreateMetricsReaderSecret, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetMetricsReaderSecret, err)
	}

	// Check if type or annotations need updating
	needsUpdate := false
	if existing.Type != desired.Type {
		existing.Type = desired.Type
		needsUpdate = true
	}
	for k, v := range desired.Annotations {
		if existing.Annotations == nil || existing.Annotations[k] != v {
			if existing.Annotations == nil {
				existing.Annotations = make(map[string]string)
			}
			existing.Annotations[k] = v
			needsUpdate = true
		}
	}

	if needsUpdate {
		logger.Info("updating metrics reader secret", "name", desired.Name)
		if err := r.Update(ctx, existing); err != nil {
			return fmt.Errorf("%s: %w", ErrUpdateMetricsReaderSecret, err)
		}
	}

	return nil
}

// reconcileNetworkPolicy ensures the app server network policy exists and is up to date.
func reconcileNetworkPolicy(r Reconciler, ctx context.Context, cfg *LCoreConfig) error {
	logger := r.GetLogger()

	desired, err := GenerateAppServerNetworkPolicy(r, cfg)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGenerateAppServerNetworkPolicy, err)
	}

	existing := &networkingv1.NetworkPolicy{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil && errors.IsNotFound(err) {
		logger.Info("creating NetworkPolicy", "name", desired.Name)
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("%s: %w", ErrCreateAppServerNetworkPolicy, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetAppServerNetworkPolicy, err)
	}

	if !NetworkPolicyEqual(existing, desired) {
		logger.Info("updating NetworkPolicy", "name", desired.Name)
		existing.Spec = desired.Spec
		if err := r.Update(ctx, existing); err != nil {
			return fmt.Errorf("%s: %w", ErrUpdateAppServerNetworkPolicy, err)
		}
	}

	return nil
}

// reconcileDeployment ensures the LCore deployment exists and is up to date.
func reconcileDeployment(r Reconciler, ctx context.Context, cfg *LCoreConfig) error {
	logger := r.GetLogger()

	desired, err := GenerateLCoreDeployment(r, ctx, cfg)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGenerateAPIDeployment, err)
	}

	existing := &appsv1.Deployment{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil && errors.IsNotFound(err) {
		logger.Info("creating Deployment", "name", desired.Name)
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("%s: %w", ErrCreateAPIDeployment, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetAPIDeployment, err)
	}

	if err := updateLCoreDeployment(r, ctx, existing, desired); err != nil {
		return fmt.Errorf("%s: %w", ErrUpdateAPIDeployment, err)
	}

	return nil
}

// updateLCoreDeployment compares the existing deployment with the desired state
// and updates it if they differ. It applies API server defaults before comparison.
func updateLCoreDeployment(r Reconciler, ctx context.Context, existing, desired *appsv1.Deployment) error {
	logger := r.GetLogger()

	// Apply defaults that the API server would set, so comparison is accurate
	SetDefaults_Deployment(desired)

	if !DeploymentSpecEqual(existing.Spec, desired.Spec) {
		logger.Info("updating Deployment", "name", existing.Name)
		existing.Spec = desired.Spec
		if err := r.Update(ctx, existing); err != nil {
			return err
		}
	}

	return nil
}

// reconcileService ensures the OLS app server service exists and is up to date.
// Always uses the service-ca annotation for TLS certificate provisioning.
func reconcileService(r Reconciler, ctx context.Context, cfg *LCoreConfig) error {
	logger := r.GetLogger()

	desired, err := GenerateService(r, cfg)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGenerateAPIService, err)
	}

	existing := &corev1.Service{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil && errors.IsNotFound(err) {
		logger.Info("creating Service", "name", desired.Name)
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("%s: %w", ErrCreateAPIService, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetAPIService, err)
	}

	if !ServiceEqual(existing, desired) {
		logger.Info("updating Service", "name", desired.Name)
		existing.Spec.Selector = desired.Spec.Selector
		existing.Spec.Ports = desired.Spec.Ports
		existing.Spec.Type = desired.Spec.Type
		if err := r.Update(ctx, existing); err != nil {
			return fmt.Errorf("%s: %w", ErrUpdateAPIService, err)
		}
	}

	return nil
}

// reconcileTLSSecret waits for the TLS secret to be populated by the service-ca
// operator with tls.key and tls.crt data.
func reconcileTLSSecret(r Reconciler, ctx context.Context, _ *LCoreConfig) error {
	logger := r.GetLogger()
	logger.Info("waiting for TLS secret to be populated", "name", OLSCertsSecretName)

	secretKey := client.ObjectKey{
		Name:      OLSCertsSecretName,
		Namespace: r.GetNamespace(),
	}

	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, ResourceCreationTimeout, true, func(ctx context.Context) (bool, error) {
		secret := &corev1.Secret{}
		if err := r.Get(ctx, secretKey, secret); err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		_, hasKey := secret.Data["tls.key"]
		_, hasCert := secret.Data["tls.crt"]
		return hasKey && hasCert, nil
	})
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGetTLSSecret, err)
	}

	logger.Info("TLS secret is ready", "name", OLSCertsSecretName)
	return nil
}

// reconcileServiceMonitor ensures the ServiceMonitor exists and is up to date.
// Skipped if Prometheus Operator CRDs are not available.
func reconcileServiceMonitor(r Reconciler, ctx context.Context, cfg *LCoreConfig) error {
	logger := r.GetLogger()

	if !r.IsPrometheusAvailable() {
		logger.Info("Prometheus Operator not available, skipping ServiceMonitor reconciliation")
		return nil
	}

	desired, err := GenerateServiceMonitor(r, cfg)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGenerateServiceMonitor, err)
	}

	existing := &monv1.ServiceMonitor{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil && errors.IsNotFound(err) {
		logger.Info("creating ServiceMonitor", "name", desired.Name)
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("%s: %w", ErrCreateServiceMonitor, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetServiceMonitor, err)
	}

	if !ServiceMonitorEqual(existing, desired) {
		logger.Info("updating ServiceMonitor", "name", desired.Name)
		existing.Spec = desired.Spec
		if err := r.Update(ctx, existing); err != nil {
			return fmt.Errorf("%s: %w", ErrUpdateServiceMonitor, err)
		}
	}

	return nil
}

// reconcilePrometheusRule ensures the PrometheusRule exists and is up to date.
// Skipped if Prometheus Operator CRDs are not available.
func reconcilePrometheusRule(r Reconciler, ctx context.Context, cfg *LCoreConfig) error {
	logger := r.GetLogger()

	if !r.IsPrometheusAvailable() {
		logger.Info("Prometheus Operator not available, skipping PrometheusRule reconciliation")
		return nil
	}

	desired, err := GeneratePrometheusRule(r, cfg)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrGeneratePrometheusRule, err)
	}

	existing := &monv1.PrometheusRule{}
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil && errors.IsNotFound(err) {
		logger.Info("creating PrometheusRule", "name", desired.Name)
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("%s: %w", ErrCreatePrometheusRule, err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("%s: %w", ErrGetPrometheusRule, err)
	}

	if !PrometheusRuleEqual(existing, desired) {
		logger.Info("updating PrometheusRule", "name", desired.Name)
		existing.Spec = desired.Spec
		if err := r.Update(ctx, existing); err != nil {
			return fmt.Errorf("%s: %w", ErrUpdatePrometheusRule, err)
		}
	}

	return nil
}
