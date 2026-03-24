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
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// GenerateLCoreDeployment generates the deployment for the LCore application.
// It delegates to either server mode or library mode based on the reconciler setting.
func GenerateLCoreDeployment(r Reconciler, ctx context.Context, cfg *LCoreConfig) (*appsv1.Deployment, error) {
	if r.GetLCoreServerMode() {
		return generateLCoreServerDeployment(r, ctx, cfg)
	}
	return generateLCoreLibraryDeployment(r, ctx, cfg)
}

// generateLCoreLibraryDeployment generates a single-container deployment where
// llama-stack runs as an embedded library within the lightspeed-stack process.
func generateLCoreLibraryDeployment(r Reconciler, ctx context.Context, cfg *LCoreConfig) (*appsv1.Deployment, error) {
	volumeDefaultMode := int32(VolumeDefaultMode)
	replicas := int32(1)

	// Build volumes and mounts
	volumes := []corev1.Volume{}
	mounts := []corev1.VolumeMount{}

	// LCore (lightspeed-stack) config
	lcoreVol, lcoreMount := buildLCoreConfigVolumeAndMount(&volumeDefaultMode)
	volumes = append(volumes, lcoreVol)
	mounts = append(mounts, lcoreMount)

	// Llama Stack config (needed in library mode)
	llamaVol, llamaMount := buildLlamaStackConfigVolumeAndMount(&volumeDefaultMode)
	volumes = append(volumes, llamaVol)
	mounts = append(mounts, llamaMount)

	// TLS volumes
	addTLSVolumesAndMounts(&volumes, &mounts, &volumeDefaultMode)

	// OpenShift CA bundles
	addOpenShiftCAVolumesAndMounts(&volumes, &mounts, &volumeDefaultMode)
	addOpenShiftRootCAVolumesAndMounts(&volumes, &mounts, &volumeDefaultMode)

	// Postgres CA
	addPostgresCAVolumesAndMounts(&volumes, &mounts)

	// User-provided additional CA
	addUserCAVolumesAndMounts(&volumes, &mounts, cfg, &volumeDefaultMode)

	// Llama cache emptydir
	addLlamaCacheVolumesAndMounts(&volumes, &mounts)

	// Data collector volumes (disabled for now)
	// dcEnabled := dataCollectorEnabled(cfg)
	// addDataCollectorVolumesAndMounts(&volumes, &mounts, &volumeDefaultMode, dcEnabled)

	// Build env vars
	llamaEnvVars, err := buildLlamaStackEnvVars(r, ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build llama-stack env vars: %w", err)
	}
	lsEnvVars := buildLightspeedStackEnvVars(r, cfg)
	envVars := append(llamaEnvVars, lsEnvVars...)
	envVars = append(envVars, buildAdditionalCAEnvVars(cfg)...)

	// Build container
	container := corev1.Container{
		Name:            "lightspeed-service-api",
		Image:           r.GetLCoreImage(),
		Ports:           []corev1.ContainerPort{{Name: "https", ContainerPort: OLSAppServerContainerPort}},
		VolumeMounts:    mounts,
		Env:             envVars,
		LivenessProbe:   buildLightspeedStackLivenessProbe(),
		ReadinessProbe:  buildLightspeedStackReadinessProbe(),
		Resources:       GetResourcesOrDefault(nil, corev1.ResourceRequirements{}),
		ImagePullPolicy: corev1.PullIfNotPresent,
		// TODO(lpiwowar): Remove me
		// Command: []string{"sleep", "infinity"},
	}

	containers := []corev1.Container{container}

	// Data collector sidecar (disabled for now)
	// addDataCollectorSidecar(r, cfg, &containers, mounts, dcEnabled)

	// Build configmap resource version annotations for change detection
	annotations, err := buildConfigMapAnnotations(r, ctx)
	if err != nil {
		return nil, err
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      LCoreDeploymentName,
			Namespace: r.GetNamespace(),
			Labels:    buildCommonLabels(),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: GenerateAppServerSelectorLabels(),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      GenerateAppServerSelectorLabels(),
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: OLSAppServerServiceAccountName,
					Containers:         containers,
					Volumes:            volumes,
				},
			},
		},
	}

	if err := controllerutil.SetControllerReference(r.GetOwner(), deployment, r.GetScheme()); err != nil {
		return nil, err
	}

	return deployment, nil
}

// generateLCoreServerDeployment generates a two-container deployment where
// llama-stack runs as a separate server container alongside lightspeed-stack.
func generateLCoreServerDeployment(r Reconciler, ctx context.Context, cfg *LCoreConfig) (*appsv1.Deployment, error) {
	volumeDefaultMode := int32(VolumeDefaultMode)
	replicas := int32(1)

	// Build shared volumes
	volumes := []corev1.Volume{}

	// Llama Stack config volume (used by llama-stack container)
	llamaVol, llamaMount := buildLlamaStackConfigVolumeAndMount(&volumeDefaultMode)
	volumes = append(volumes, llamaVol)

	// LCore config volume (used by lightspeed-stack container)
	lcoreVol, lcoreMount := buildLCoreConfigVolumeAndMount(&volumeDefaultMode)
	volumes = append(volumes, lcoreVol)

	// Shared volumes - TLS, CA, postgres
	sharedMounts := []corev1.VolumeMount{}
	addTLSVolumesAndMounts(&volumes, &sharedMounts, &volumeDefaultMode)
	addOpenShiftCAVolumesAndMounts(&volumes, &sharedMounts, &volumeDefaultMode)
	addOpenShiftRootCAVolumesAndMounts(&volumes, &sharedMounts, &volumeDefaultMode)
	addPostgresCAVolumesAndMounts(&volumes, &sharedMounts)
	addUserCAVolumesAndMounts(&volumes, &sharedMounts, cfg, &volumeDefaultMode)

	// Llama cache emptydir
	llamaCacheMounts := []corev1.VolumeMount{}
	addLlamaCacheVolumesAndMounts(&volumes, &llamaCacheMounts)

	// Data collector volumes (disabled for now)
	// dcEnabled := dataCollectorEnabled(cfg)
	// dcMounts := []corev1.VolumeMount{}
	// addDataCollectorVolumesAndMounts(&volumes, &dcMounts, &volumeDefaultMode, dcEnabled)

	// Build env vars
	llamaEnvVars, err := buildLlamaStackEnvVars(r, ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build llama-stack env vars: %w", err)
	}
	lsEnvVars := buildLightspeedStackEnvVars(r, cfg)

	// Llama Stack container mounts: its config + shared + cache
	llamaStackMounts := []corev1.VolumeMount{llamaMount}
	llamaStackMounts = append(llamaStackMounts, sharedMounts...)
	llamaStackMounts = append(llamaStackMounts, llamaCacheMounts...)

	// Llama-stack needs POSTGRES_PASSWORD for ${env.POSTGRES_PASSWORD} substitution in its config
	llamaStackEnvVars := append(llamaEnvVars,
		buildPostgresPasswordEnvVar(r),
		corev1.EnvVar{
			Name:  "LLAMA_STACK_LOGGING",
			Value: "all=debug",
		},
	)
	llamaStackEnvVars = append(llamaStackEnvVars, buildAdditionalCAEnvVars(cfg)...)

	llamaStackContainer := corev1.Container{
		Name:            "llama-stack",
		Image:           r.GetLCoreImage(),
		Command:         []string{"llama", "stack", "run", LlamaStackConfigMountPath},
		Ports:           []corev1.ContainerPort{{Name: "llama-stack", ContainerPort: 8321}},
		VolumeMounts:    llamaStackMounts,
		Env:             llamaStackEnvVars,
		Resources:       GetResourcesOrDefault(nil, corev1.ResourceRequirements{}),
		ImagePullPolicy: corev1.PullIfNotPresent,
	}

	// Lightspeed Stack container mounts: its config + shared
	lightspeedStackMounts := []corev1.VolumeMount{lcoreMount}
	lightspeedStackMounts = append(lightspeedStackMounts, sharedMounts...)

	lightspeedStackContainer := corev1.Container{
		Name:            "lightspeed-service-api",
		Image:           r.GetLCoreImage(),
		Ports:           []corev1.ContainerPort{{Name: "https", ContainerPort: OLSAppServerContainerPort}},
		VolumeMounts:    lightspeedStackMounts,
		Env:             lsEnvVars,
		LivenessProbe:   buildLightspeedStackLivenessProbe(),
		ReadinessProbe:  buildLightspeedStackReadinessProbe(),
		Resources:       GetResourcesOrDefault(nil, corev1.ResourceRequirements{}),
		ImagePullPolicy: corev1.PullIfNotPresent,
	}

	containers := []corev1.Container{llamaStackContainer, lightspeedStackContainer}

	// Data collector sidecar (disabled for now)
	// addDataCollectorSidecar(r, cfg, &containers, lightspeedStackMounts, dcEnabled)

	// Build configmap resource version annotations for change detection
	annotations, err := buildConfigMapAnnotations(r, ctx)
	if err != nil {
		return nil, err
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      LCoreDeploymentName,
			Namespace: r.GetNamespace(),
			Labels:    buildCommonLabels(),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: GenerateAppServerSelectorLabels(),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      GenerateAppServerSelectorLabels(),
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: OLSAppServerServiceAccountName,
					Containers:         containers,
					Volumes:            volumes,
				},
			},
		},
	}

	if err := controllerutil.SetControllerReference(r.GetOwner(), deployment, r.GetScheme()); err != nil {
		return nil, err
	}

	return deployment, nil
}

// =============================================================================
// Helper functions
// =============================================================================

// buildCommonLabels returns common labels for the lightspeed-stack deployment.
func buildCommonLabels() map[string]string {
	labels := GenerateAppServerSelectorLabels()
	labels["app"] = "lightspeed-stack"
	return labels
}

// buildLCoreConfigVolumeAndMount returns the volume and mount for the lightspeed-stack config.
func buildLCoreConfigVolumeAndMount(volumeDefaultMode *int32) (corev1.Volume, corev1.VolumeMount) {
	vol := corev1.Volume{
		Name: "lcore-config",
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: LCoreConfigCmName,
				},
				DefaultMode: volumeDefaultMode,
			},
		},
	}
	mount := corev1.VolumeMount{
		Name:      "lcore-config",
		MountPath: LCoreConfigMountPath,
		SubPath:   LCoreConfigFilename,
		ReadOnly:  true,
	}
	return vol, mount
}

// buildLlamaStackConfigVolumeAndMount returns the volume and mount for the llama-stack config.
func buildLlamaStackConfigVolumeAndMount(volumeDefaultMode *int32) (corev1.Volume, corev1.VolumeMount) {
	vol := corev1.Volume{
		Name: "llama-stack-config",
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: LlamaStackConfigCmName,
				},
				DefaultMode: volumeDefaultMode,
			},
		},
	}
	mount := corev1.VolumeMount{
		Name:      "llama-stack-config",
		MountPath: LlamaStackConfigMountPath,
		SubPath:   LlamaStackConfigFilename,
		ReadOnly:  true,
	}
	return vol, mount
}

// addTLSVolumesAndMounts adds the service-ca TLS certificate volume and mount.
func addTLSVolumesAndMounts(volumes *[]corev1.Volume, mounts *[]corev1.VolumeMount, volumeDefaultMode *int32) {
	*volumes = append(*volumes, corev1.Volume{
		Name: "tls-certs",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName:  OLSCertsSecretName,
				DefaultMode: volumeDefaultMode,
			},
		},
	})
	*mounts = append(*mounts, corev1.VolumeMount{
		Name:      "tls-certs",
		MountPath: OLSAppCertsMountRoot + "/lightspeed-tls",
		ReadOnly:  true,
	})
}

// addOpenShiftCAVolumesAndMounts adds the OpenShift service-ca CA bundle volume and mount.
func addOpenShiftCAVolumesAndMounts(volumes *[]corev1.Volume, mounts *[]corev1.VolumeMount, volumeDefaultMode *int32) {
	*volumes = append(*volumes, corev1.Volume{
		Name: OpenShiftCAVolumeName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: OLSCAConfigMap,
				},
				DefaultMode: volumeDefaultMode,
			},
		},
	})
	*mounts = append(*mounts, corev1.VolumeMount{
		Name:      OpenShiftCAVolumeName,
		MountPath: OLSAppCertsMountRoot + "/openshift-ca",
		ReadOnly:  true,
	})
}

// addOpenShiftRootCAVolumesAndMounts adds the OpenShift cluster-wide root CA bundle.
func addOpenShiftRootCAVolumesAndMounts(volumes *[]corev1.Volume, mounts *[]corev1.VolumeMount, volumeDefaultMode *int32) {
	*volumes = append(*volumes, corev1.Volume{
		Name: "openshift-root-ca",
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "kube-root-ca.crt",
				},
				DefaultMode: volumeDefaultMode,
			},
		},
	})
	*mounts = append(*mounts, corev1.VolumeMount{
		Name:      "openshift-root-ca",
		MountPath: OLSAppCertsMountRoot + "/openshift-root-ca",
		ReadOnly:  true,
	})
}

// addPostgresCAVolumesAndMounts adds the Postgres CA certificate volume and mount.
func addPostgresCAVolumesAndMounts(volumes *[]corev1.Volume, mounts *[]corev1.VolumeMount) {
	*volumes = append(*volumes, GetPostgresCAConfigVolume())
	*mounts = append(*mounts, GetPostgresCAVolumeMount())
}

// addLlamaCacheVolumesAndMounts adds an emptydir volume for llama-stack cache.
func addLlamaCacheVolumesAndMounts(volumes *[]corev1.Volume, mounts *[]corev1.VolumeMount) {
	*volumes = append(*volumes, corev1.Volume{
		Name: "llama-cache",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	})
	*mounts = append(*mounts, corev1.VolumeMount{
		Name:      "llama-cache",
		MountPath: "/tmp/llama-stack",
	})
}

// addUserCAVolumesAndMounts adds user-provided additional CA certificate volume and mount
// if cfg.AdditionalCAConfigMapName is set.
func addUserCAVolumesAndMounts(volumes *[]corev1.Volume, mounts *[]corev1.VolumeMount, cfg *LCoreConfig, volumeDefaultMode *int32) {
	if cfg.AdditionalCAConfigMapName == "" {
		return
	}
	*volumes = append(*volumes, corev1.Volume{
		Name: AdditionalCAVolumeName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: cfg.AdditionalCAConfigMapName,
				},
				DefaultMode: volumeDefaultMode,
			},
		},
	})
	*mounts = append(*mounts, corev1.VolumeMount{
		Name:      AdditionalCAVolumeName,
		MountPath: OLSAppCertsMountRoot + "/additional-ca",
		ReadOnly:  true,
	})
}

// buildAdditionalCAEnvVars returns REQUESTS_CA_BUNDLE and SSL_CERT_FILE env vars
// pointing to the additional CA cert file, if an additional CA configmap is configured.
func buildAdditionalCAEnvVars(cfg *LCoreConfig) []corev1.EnvVar {
	if cfg.AdditionalCAConfigMapName == "" {
		return nil
	}
	certPath := OLSAppCertsMountRoot + "/additional-ca/" + AdditionalCACertFile
	return []corev1.EnvVar{
		{
			Name:  "REQUESTS_CA_BUNDLE",
			Value: certPath,
		},
		{
			Name:  "SSL_CERT_FILE",
			Value: certPath,
		},
	}
}

// addDataCollectorVolumesAndMounts adds the user data and exporter config volumes
// when data collection is enabled.
func addDataCollectorVolumesAndMounts(volumes *[]corev1.Volume, mounts *[]corev1.VolumeMount, volumeDefaultMode *int32, enabled bool) {
	if !enabled {
		return
	}

	// User data emptydir for feedback/transcripts
	*volumes = append(*volumes, corev1.Volume{
		Name: "user-data",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	})
	*mounts = append(*mounts, corev1.VolumeMount{
		Name:      "user-data",
		MountPath: LCoreUserDataMountPath,
	})

	// Exporter config
	*volumes = append(*volumes, corev1.Volume{
		Name: ExporterConfigVolumeName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: ExporterConfigCmName,
				},
				DefaultMode: volumeDefaultMode,
			},
		},
	})
}

// addDataCollectorSidecar adds the data exporter sidecar container if data collection is enabled.
func addDataCollectorSidecar(r Reconciler, _ *LCoreConfig, containers *[]corev1.Container, _ []corev1.VolumeMount, enabled bool) {
	if !enabled {
		return
	}

	sidecarMounts := []corev1.VolumeMount{
		{
			Name:      "user-data",
			MountPath: LCoreUserDataMountPath,
			ReadOnly:  true,
		},
		{
			Name:      ExporterConfigVolumeName,
			MountPath: ExporterConfigMountPath,
			ReadOnly:  true,
		},
	}

	sidecar := corev1.Container{
		Name:            "data-collector",
		Image:           r.GetDataverseExporterImage(),
		VolumeMounts:    sidecarMounts,
		Resources:       GetResourcesOrDefault(nil, corev1.ResourceRequirements{}),
		ImagePullPolicy: corev1.PullIfNotPresent,
	}

	*containers = append(*containers, sidecar)
}

// =============================================================================
// Environment variable builders
// =============================================================================

// buildLlamaStackEnvVars builds environment variables for llama-stack,
// primarily provider API keys read from Kubernetes secrets.
func buildLlamaStackEnvVars(r Reconciler, ctx context.Context, cfg *LCoreConfig) ([]corev1.EnvVar, error) {
	envVars := []corev1.EnvVar{}

	for _, provider := range cfg.Providers {
		if provider.CredentialsSecret == "" {
			continue
		}

		envVarName := ProviderNameToEnvVarName(provider.Name)

		if provider.Type == AzureOpenAIType {
			// Azure supports both API key and client credentials authentication.
			// Read the secret to determine which fields are present.
			secret := &corev1.Secret{}
			err := r.Get(ctx, types.NamespacedName{
				Name:      provider.CredentialsSecret,
				Namespace: r.GetNamespace(),
			}, secret)
			if err != nil {
				return nil, fmt.Errorf("failed to get Azure provider secret %s: %w", provider.CredentialsSecret, err)
			}

			// API key (always include - required by LiteLLM's Pydantic validation)
			if _, ok := secret.Data["apitoken"]; ok {
				envVars = append(envVars, corev1.EnvVar{
					Name: envVarName + "_API_KEY",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: provider.CredentialsSecret,
							},
							Key: "apitoken",
						},
					},
				})
			} else {
				// Provide an empty default so the env var exists
				envVars = append(envVars, corev1.EnvVar{
					Name:  envVarName + "_API_KEY",
					Value: "",
				})
			}

			// Client credentials fields for Azure AD authentication
			for _, field := range []struct {
				secretKey string
				envSuffix string
			}{
				{"client_id", "_CLIENT_ID"},
				{"tenant_id", "_TENANT_ID"},
				{"client_secret", "_CLIENT_SECRET"},
			} {
				if _, ok := secret.Data[field.secretKey]; ok {
					envVars = append(envVars, corev1.EnvVar{
						Name: envVarName + field.envSuffix,
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: provider.CredentialsSecret,
								},
								Key: field.secretKey,
							},
						},
					})
				} else {
					envVars = append(envVars, corev1.EnvVar{
						Name:  envVarName + field.envSuffix,
						Value: "",
					})
				}
			}
		} else {
			// Non-Azure providers: single API_KEY from the "apitoken" key
			envVars = append(envVars, corev1.EnvVar{
				Name: envVarName + "_API_KEY",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: provider.CredentialsSecret,
						},
						Key: "apitoken",
					},
				},
			})

			// For vLLM providers, also set the URL environment variable
			// The vLLM adapter checks for VLLM_URL as a fallback if URL is not in config
			if provider.Type == "rhoai_vllm" || provider.Type == "rhelai_vllm" {
				if provider.URL != "" {
					envVars = append(envVars, corev1.EnvVar{
						Name:  "VLLM_URL",
						Value: provider.URL,
					})
				}
			}
		}
	}

	return envVars, nil
}

// buildPostgresPasswordEnvVar returns the POSTGRES_PASSWORD env var sourced from the postgres secret.
func buildPostgresPasswordEnvVar(r Reconciler) corev1.EnvVar {
	return corev1.EnvVar{
		Name: "POSTGRES_PASSWORD",
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: PostgresSecretName,
				},
				Key: OLSComponentPasswordFileName,
			},
		},
	}
}

// buildLightspeedStackEnvVars builds environment variables for the lightspeed-stack container.
func buildLightspeedStackEnvVars(r Reconciler, _ *LCoreConfig) []corev1.EnvVar {
	return []corev1.EnvVar{
		{
			Name:  "LOG_LEVEL",
			Value: "DEBUG",
		},
		{
			Name:  "LLAMA_STACK_LOGGING",
			Value: "all=debug",
		},
		buildPostgresPasswordEnvVar(r),
	}
}

// =============================================================================
// Probes
// =============================================================================

// buildLightspeedStackLivenessProbe returns the liveness probe for the lightspeed-stack container.
func buildLightspeedStackLivenessProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: []string{
					"curl", "-ks", "https://localhost:8443/liveness",
				},
			},
		},
		InitialDelaySeconds: 30,
		PeriodSeconds:       10,
		TimeoutSeconds:      5,
		FailureThreshold:    3,
	}
}

// buildLightspeedStackReadinessProbe returns the readiness probe for the lightspeed-stack container.
func buildLightspeedStackReadinessProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: []string{
					"curl", "-ks", "https://localhost:8443/readiness",
				},
			},
		},
		InitialDelaySeconds: 30,
		PeriodSeconds:       10,
		TimeoutSeconds:      5,
		FailureThreshold:    3,
	}
}

// =============================================================================
// Deployment update and restart
// =============================================================================

// RestartLCore triggers a rolling restart of the LCore deployment by updating
// the force-reload annotation on the pod template. If no deployment is provided,
// it fetches the current one.
func RestartLCore(r Reconciler, ctx context.Context, deployments ...*appsv1.Deployment) error {
	var deployment *appsv1.Deployment

	if len(deployments) > 0 && deployments[0] != nil {
		deployment = deployments[0]
	} else {
		deployment = &appsv1.Deployment{}
		err := r.Get(ctx, types.NamespacedName{
			Name:      LCoreDeploymentName,
			Namespace: r.GetNamespace(),
		}, deployment)
		if err != nil {
			if errors.IsNotFound(err) {
				// Deployment doesn't exist yet, nothing to restart
				return nil
			}
			return fmt.Errorf("failed to get LCore deployment for restart: %w", err)
		}
	}

	if deployment.Spec.Template.ObjectMeta.Annotations == nil {
		deployment.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
	}

	deployment.Spec.Template.ObjectMeta.Annotations[ForceReloadAnnotationKey] = fmt.Sprintf("%d", time.Now().UnixNano())

	if err := r.Update(ctx, deployment); err != nil {
		return fmt.Errorf("failed to restart LCore deployment: %w", err)
	}

	r.GetLogger().Info("Triggered LCore deployment restart")
	return nil
}

// =============================================================================
// Data collector helpers
// =============================================================================

// dataCollectorEnabled returns true if at least one data collection feature
// (feedback or transcripts) is enabled.
func dataCollectorEnabled(cfg *LCoreConfig) bool {
	return !cfg.FeedbackDisabled || !cfg.TranscriptsDisabled
}

// =============================================================================
// Internal helpers
// =============================================================================

// buildConfigMapAnnotations builds annotations with configmap resource versions
// so that changes to the configmaps trigger a deployment rollout.
func buildConfigMapAnnotations(r Reconciler, ctx context.Context) (map[string]string, error) {
	annotations := make(map[string]string)

	lcoreVersion, err := GetConfigMapResourceVersion(ctx, r, LCoreConfigCmName, r.GetNamespace())
	if err != nil {
		// ConfigMap may not exist yet during initial creation
		if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get LCore configmap resource version: %w", err)
		}
	} else {
		annotations[LCoreConfigMapResourceVersionAnnotation] = lcoreVersion
	}

	llamaVersion, err := GetConfigMapResourceVersion(ctx, r, LlamaStackConfigCmName, r.GetNamespace())
	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get Llama Stack configmap resource version: %w", err)
		}
	} else {
		annotations[LlamaStackConfigMapResourceVersionAnnotation] = llamaVersion
	}

	return annotations, nil
}
