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
	"path"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// GeneratePostgresDeployment generates the Postgres Deployment object.
func GeneratePostgresDeployment(r Reconciler, ctx context.Context) (*appsv1.Deployment, error) {
	replicas := int32(1)
	revisionHistoryLimit := int32(1)

	passwordMap, err := GetSecretContent(ctx, r, PostgresSecretName, r.GetNamespace(), []string{OLSComponentPasswordFileName})
	if err != nil {
		return nil, fmt.Errorf("password is needed to start postgres deployment: %w", err)
	}
	postgresPassword := passwordMap[OLSComponentPasswordFileName]

	// Build volumes and volume mounts
	volumes := []corev1.Volume{}
	volumeMounts := []corev1.VolumeMount{}

	restrictedMode := VolumeRestrictedMode
	defaultMode := VolumeDefaultMode

	// TLS certs volume (auto-provisioned by service-ca via the Service annotation)
	volumes = append(volumes, corev1.Volume{
		Name: "secret-" + PostgresCertsSecretName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName:  PostgresCertsSecretName,
				DefaultMode: &restrictedMode,
			},
		},
	})
	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      "secret-" + PostgresCertsSecretName,
		MountPath: OLSAppCertsMountRoot,
		ReadOnly:  true,
	})

	// Bootstrap script volume
	volumes = append(volumes, corev1.Volume{
		Name: "secret-" + PostgresBootstrapSecretName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName:  PostgresBootstrapSecretName,
				DefaultMode: &restrictedMode,
			},
		},
	})
	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      "secret-" + PostgresBootstrapSecretName,
		MountPath: PostgresBootstrapVolumeMountPath,
		SubPath:   PostgresExtensionScript,
		ReadOnly:  true,
	})

	// Postgres config volume
	volumes = append(volumes, corev1.Volume{
		Name: PostgresConfigMapName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: PostgresConfigMapName},
				DefaultMode:          &defaultMode,
			},
		},
	})
	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      PostgresConfigMapName,
		MountPath: PostgresConfigVolumeMountPath,
		SubPath:   PostgresConfigKey,
	})

	// Data volume (EmptyDir for now — no persistence)
	volumes = append(volumes, corev1.Volume{
		Name: PostgresDataVolume,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	})
	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      PostgresDataVolume,
		MountPath: PostgresDataVolumeMountPath,
	})

	// Postgres CA volume
	volumes = append(volumes, GetPostgresCAConfigVolume())
	volumeMounts = append(volumeMounts, GetPostgresCAVolumeMountWithPath(path.Join(OLSAppCertsMountRoot, PostgresCAVolume)))

	// Var run volume (writable runtime directory)
	volumes = append(volumes, corev1.Volume{
		Name: PostgresVarRunVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	})
	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      PostgresVarRunVolumeName,
		MountPath: PostgresVarRunVolumeMountPath,
	})

	// Tmp volume (writable temp directory)
	volumes = append(volumes, corev1.Volume{
		Name: TmpVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	})
	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      TmpVolumeName,
		MountPath: TmpVolumeMountPath,
	})

	// Build configmap resource version annotation for change detection
	configMapResourceVersion, _ := GetConfigMapResourceVersion(ctx, r, PostgresConfigMapName, r.GetNamespace())

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PostgresDeploymentName,
			Namespace: r.GetNamespace(),
			Labels:    GeneratePostgresSelectorLabels(),
			Annotations: map[string]string{
				PostgresConfigMapResourceVersionAnnotation: configMapResourceVersion,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: GeneratePostgresSelectorLabels(),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: GeneratePostgresSelectorLabels(),
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            PostgresDeploymentName,
							Image:           r.GetPostgresImage(),
							ImagePullPolicy: corev1.PullAlways,
							Ports: []corev1.ContainerPort{
								{
									Name:          "server",
									ContainerPort: PostgresServicePort,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: &[]bool{false}[0],
								ReadOnlyRootFilesystem:   &[]bool{true}[0],
							},
							VolumeMounts: volumeMounts,
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("30m"),
									corev1.ResourceMemory: resource.MustParse("300Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("2Gi"),
								},
							},
							Env: []corev1.EnvVar{
								{
									Name:  "POSTGRESQL_USER",
									Value: PostgresDefaultUser,
								},
								{
									Name:  "POSTGRESQL_DATABASE",
									Value: PostgresDefaultDbName,
								},
								{
									Name:  "POSTGRESQL_ADMIN_PASSWORD",
									Value: postgresPassword,
								},
								{
									Name:  "POSTGRESQL_PASSWORD",
									Value: postgresPassword,
								},
								{
									Name:  "POSTGRESQL_SHARED_BUFFERS",
									Value: PostgresSharedBuffers,
								},
								{
									Name:  "POSTGRESQL_MAX_CONNECTIONS",
									Value: strconv.Itoa(PostgresMaxConnections),
								},
							},
						},
					},
					Volumes: volumes,
				},
			},
			RevisionHistoryLimit: &revisionHistoryLimit,
		},
	}

	if err := controllerutil.SetControllerReference(r.GetOwner(), deployment, r.GetScheme()); err != nil {
		return nil, err
	}

	return deployment, nil
}

// UpdatePostgresDeployment updates the Postgres deployment if specs or configmap version have changed.
func UpdatePostgresDeployment(r Reconciler, ctx context.Context, existingDeployment, desiredDeployment *appsv1.Deployment) error {
	SetDefaults_Deployment(desiredDeployment)
	changed := !DeploymentSpecEqual(existingDeployment.Spec, desiredDeployment.Spec)

	// Check if ConfigMap ResourceVersion has changed
	currentConfigMapVersion, err := GetConfigMapResourceVersion(ctx, r, PostgresConfigMapName, r.GetNamespace())
	if err != nil {
		r.GetLogger().Info("failed to get Postgres ConfigMap ResourceVersion", "error", err)
		changed = true
	} else {
		storedVersion := existingDeployment.Annotations[PostgresConfigMapResourceVersionAnnotation]
		if storedVersion != currentConfigMapVersion {
			changed = true
		}
	}

	if !changed {
		return nil
	}

	existingDeployment.Spec = desiredDeployment.Spec
	if existingDeployment.Annotations == nil {
		existingDeployment.Annotations = make(map[string]string)
	}
	existingDeployment.Annotations[PostgresConfigMapResourceVersionAnnotation] = desiredDeployment.Annotations[PostgresConfigMapResourceVersionAnnotation]

	r.GetLogger().Info("updating Postgres deployment", "name", existingDeployment.Name)

	if err := RestartPostgres(r, ctx, existingDeployment); err != nil {
		return err
	}

	return nil
}
