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
	"strings"

	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ConfigMapEqual compares two ConfigMaps for equality.
// Returns true if their Data and BinaryData fields are semantically equal.
func ConfigMapEqual(existing, desired *corev1.ConfigMap) bool {
	return apiequality.Semantic.DeepEqual(existing.Data, desired.Data) &&
		apiequality.Semantic.DeepEqual(existing.BinaryData, desired.BinaryData)
}

// ServiceEqual compares two Services for equality.
// Returns true if their Spec.Selector, Spec.Ports, and Spec.Type are semantically equal.
func ServiceEqual(existing, desired *corev1.Service) bool {
	return apiequality.Semantic.DeepEqual(existing.Spec.Selector, desired.Spec.Selector) &&
		apiequality.Semantic.DeepEqual(existing.Spec.Ports, desired.Spec.Ports) &&
		existing.Spec.Type == desired.Spec.Type
}

// NetworkPolicyEqual compares two NetworkPolicies for equality.
// Returns true if their Spec fields are semantically equal.
func NetworkPolicyEqual(existing, desired *networkingv1.NetworkPolicy) bool {
	return apiequality.Semantic.DeepEqual(existing.Spec, desired.Spec)
}

// ServiceMonitorEqual compares two ServiceMonitors for equality.
// Returns true if their Spec fields are semantically equal.
func ServiceMonitorEqual(existing, desired *monv1.ServiceMonitor) bool {
	return apiequality.Semantic.DeepEqual(existing.Spec, desired.Spec)
}

// PrometheusRuleEqual compares two PrometheusRules for equality.
// Returns true if their Spec fields are semantically equal.
func PrometheusRuleEqual(existing, desired *monv1.PrometheusRule) bool {
	return apiequality.Semantic.DeepEqual(existing.Spec, desired.Spec)
}

// DeploymentSpecEqual compares two DeploymentSpecs for equality.
// It checks Replicas, Selector, and the pod template's containers and volumes.
func DeploymentSpecEqual(existing, desired appsv1.DeploymentSpec) bool {
	if !apiequality.Semantic.DeepEqual(existing.Replicas, desired.Replicas) {
		return false
	}
	if !apiequality.Semantic.DeepEqual(existing.Selector, desired.Selector) {
		return false
	}
	if !ContainersEqual(existing.Template.Spec.Containers, desired.Template.Spec.Containers) {
		return false
	}
	if !ContainersEqual(existing.Template.Spec.InitContainers, desired.Template.Spec.InitContainers) {
		return false
	}
	if !PodVolumeEqual(existing.Template.Spec.Volumes, desired.Template.Spec.Volumes) {
		return false
	}
	if !apiequality.Semantic.DeepEqual(existing.Template.ObjectMeta.Labels, desired.Template.ObjectMeta.Labels) {
		return false
	}
	if !apiequality.Semantic.DeepEqual(existing.Template.ObjectMeta.Annotations, desired.Template.ObjectMeta.Annotations) {
		return false
	}
	return true
}

// ContainersEqual compares two slices of containers for equality.
func ContainersEqual(existing, desired []corev1.Container) bool {
	if len(existing) != len(desired) {
		return false
	}
	for i := range existing {
		if !ContainerSpecEqual(existing[i], desired[i]) {
			return false
		}
	}
	return true
}

// ContainerSpecEqual compares two container specs for equality.
// It checks Name, Image, Ports, Env, VolumeMounts, Resources, Command, Args, and Probes.
func ContainerSpecEqual(existing, desired corev1.Container) bool {
	if existing.Name != desired.Name {
		return false
	}
	if existing.Image != desired.Image {
		return false
	}
	if !apiequality.Semantic.DeepEqual(existing.Ports, desired.Ports) {
		return false
	}
	if !EnvEqual(existing.Env, desired.Env) {
		return false
	}
	if !VolumeMountsEqual(existing.VolumeMounts, desired.VolumeMounts) {
		return false
	}
	if !apiequality.Semantic.DeepEqual(existing.Resources, desired.Resources) {
		return false
	}
	if !apiequality.Semantic.DeepEqual(existing.Command, desired.Command) {
		return false
	}
	if !apiequality.Semantic.DeepEqual(existing.Args, desired.Args) {
		return false
	}
	if !ProbeEqual(existing.LivenessProbe, desired.LivenessProbe) {
		return false
	}
	if !ProbeEqual(existing.ReadinessProbe, desired.ReadinessProbe) {
		return false
	}
	if !ProbeEqual(existing.StartupProbe, desired.StartupProbe) {
		return false
	}
	return true
}

// EnvEqual compares two slices of environment variables for equality.
func EnvEqual(existing, desired []corev1.EnvVar) bool {
	if len(existing) != len(desired) {
		return false
	}
	for i := range existing {
		if existing[i].Name != desired[i].Name {
			return false
		}
		if existing[i].Value != desired[i].Value {
			return false
		}
		if !apiequality.Semantic.DeepEqual(existing[i].ValueFrom, desired[i].ValueFrom) {
			return false
		}
	}
	return true
}

// VolumeMountsEqual compares two slices of volume mounts for equality.
func VolumeMountsEqual(existing, desired []corev1.VolumeMount) bool {
	if len(existing) != len(desired) {
		return false
	}
	for i := range existing {
		if existing[i].Name != desired[i].Name {
			return false
		}
		if existing[i].MountPath != desired[i].MountPath {
			return false
		}
		if existing[i].SubPath != desired[i].SubPath {
			return false
		}
		if existing[i].ReadOnly != desired[i].ReadOnly {
			return false
		}
	}
	return true
}

// ProbeEqual compares two Probes for equality.
// Returns true if both are nil, or if both are non-nil and semantically equal.
func ProbeEqual(existing, desired *corev1.Probe) bool {
	if existing == nil && desired == nil {
		return true
	}
	if existing == nil || desired == nil {
		return false
	}
	return apiequality.Semantic.DeepEqual(existing, desired)
}

// PodVolumeEqual compares two slices of volumes for equality.
func PodVolumeEqual(existing, desired []corev1.Volume) bool {
	if len(existing) != len(desired) {
		return false
	}
	for i := range existing {
		if existing[i].Name != desired[i].Name {
			return false
		}
		if !apiequality.Semantic.DeepEqual(existing[i].VolumeSource, desired[i].VolumeSource) {
			return false
		}
	}
	return true
}

// GenerateAppServerSelectorLabels returns a map of labels used as selectors
// for the application server pods.
func GenerateAppServerSelectorLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/component":  "app-server",
		"app.kubernetes.io/managed-by": "lightspeed-operator",
		"app.kubernetes.io/name":       "lightspeed-app-server",
		"app.kubernetes.io/part-of":    "openstack-lightspeed",
	}
}

// GetSecretContent retrieves the content of specific keys from a Kubernetes Secret.
// It returns a map of key to decoded value for each requested key.
func GetSecretContent(ctx context.Context, r Reconciler, secretName string, namespace string, keys []string) (map[string]string, error) {
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: namespace}, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s: %w", secretName, err)
	}

	result := make(map[string]string, len(keys))
	for _, key := range keys {
		data, ok := secret.Data[key]
		if !ok {
			return nil, fmt.Errorf("key %q not found in secret %s", key, secretName)
		}
		result[key] = string(data)
	}
	return result, nil
}

// GetConfigMapResourceVersion retrieves the resource version of a ConfigMap.
func GetConfigMapResourceVersion(ctx context.Context, r Reconciler, name string, namespace string) (string, error) {
	cm := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, cm)
	if err != nil {
		return "", fmt.Errorf("failed to get configmap %s: %w", name, err)
	}
	return cm.ResourceVersion, nil
}

// SetDefaults_Deployment sets Kubernetes deployment defaults that are normally
// applied by the API server. This is useful when comparing desired vs existing
// deployments, as the existing deployment will have these defaults set.
func SetDefaults_Deployment(deployment *appsv1.Deployment) {
	// Set default replicas to 1
	if deployment.Spec.Replicas == nil {
		one := int32(1)
		deployment.Spec.Replicas = &one
	}

	// Set default strategy
	if deployment.Spec.Strategy.Type == "" {
		deployment.Spec.Strategy.Type = appsv1.RollingUpdateDeploymentStrategyType
	}
	if deployment.Spec.Strategy.Type == appsv1.RollingUpdateDeploymentStrategyType &&
		deployment.Spec.Strategy.RollingUpdate == nil {
		deployment.Spec.Strategy.RollingUpdate = &appsv1.RollingUpdateDeployment{
			MaxUnavailable: &intstr.IntOrString{Type: intstr.String, StrVal: "25%"},
			MaxSurge:       &intstr.IntOrString{Type: intstr.String, StrVal: "25%"},
		}
	}

	// Set default revision history limit
	if deployment.Spec.RevisionHistoryLimit == nil {
		ten := int32(10)
		deployment.Spec.RevisionHistoryLimit = &ten
	}

	// Set default progress deadline seconds
	if deployment.Spec.ProgressDeadlineSeconds == nil {
		sixHundred := int32(600)
		deployment.Spec.ProgressDeadlineSeconds = &sixHundred
	}

	// Set default pod template spec values
	for i := range deployment.Spec.Template.Spec.Containers {
		c := &deployment.Spec.Template.Spec.Containers[i]
		if c.TerminationMessagePath == "" {
			c.TerminationMessagePath = "/dev/termination-log"
		}
		if c.TerminationMessagePolicy == "" {
			c.TerminationMessagePolicy = corev1.TerminationMessageReadFile
		}
		if c.ImagePullPolicy == "" {
			c.ImagePullPolicy = corev1.PullIfNotPresent
		}
	}
	for i := range deployment.Spec.Template.Spec.InitContainers {
		c := &deployment.Spec.Template.Spec.InitContainers[i]
		if c.TerminationMessagePath == "" {
			c.TerminationMessagePath = "/dev/termination-log"
		}
		if c.TerminationMessagePolicy == "" {
			c.TerminationMessagePolicy = corev1.TerminationMessageReadFile
		}
		if c.ImagePullPolicy == "" {
			c.ImagePullPolicy = corev1.PullIfNotPresent
		}
	}

	if deployment.Spec.Template.Spec.RestartPolicy == "" {
		deployment.Spec.Template.Spec.RestartPolicy = corev1.RestartPolicyAlways
	}
	if deployment.Spec.Template.Spec.TerminationGracePeriodSeconds == nil {
		thirty := int64(30)
		deployment.Spec.Template.Spec.TerminationGracePeriodSeconds = &thirty
	}
	if deployment.Spec.Template.Spec.DNSPolicy == "" {
		deployment.Spec.Template.Spec.DNSPolicy = corev1.DNSClusterFirst
	}
	if deployment.Spec.Template.Spec.SchedulerName == "" {
		deployment.Spec.Template.Spec.SchedulerName = "default-scheduler"
	}
}

// ProviderNameToEnvVarName converts a provider name to a valid environment variable name.
// It uppercases the string and replaces hyphens and dots with underscores.
func ProviderNameToEnvVarName(providerName string) string {
	name := strings.ToUpper(providerName)
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ReplaceAll(name, ".", "_")
	return name
}

// GetPostgresCAConfigVolume returns a Volume for the Postgres CA certificate ConfigMap.
func GetPostgresCAConfigVolume() corev1.Volume {
	defaultMode := VolumeDefaultMode
	return corev1.Volume{
		Name: PostgresCAVolume,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: OLSCAConfigMap,
				},
				DefaultMode: &defaultMode,
			},
		},
	}
}

// GetPostgresCAVolumeMount returns a VolumeMount for the Postgres CA certificate.
func GetPostgresCAVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      PostgresCAVolume,
		MountPath: OLSAppCertsMountRoot + "/postgres-ca",
		ReadOnly:  true,
	}
}

// GetPostgresCAVolumeMountWithPath returns a VolumeMount for the Postgres CA certificate
// at the specified mount path. Used by the postgres container itself.
func GetPostgresCAVolumeMountWithPath(mountPath string) corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      PostgresCAVolume,
		MountPath: mountPath,
		ReadOnly:  true,
	}
}

// GeneratePostgresSelectorLabels returns selector labels for Postgres components.
func GeneratePostgresSelectorLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/component":  "postgres-server",
		"app.kubernetes.io/managed-by": "lightspeed-operator",
		"app.kubernetes.io/name":       "lightspeed-service-postgres",
		"app.kubernetes.io/part-of":    "openshift-lightspeed",
	}
}

// IsPrometheusOperatorAvailable checks if the Prometheus Operator CRDs are installed
// in the cluster by looking for the ServiceMonitor CRD.
func IsPrometheusOperatorAvailable(ctx context.Context, c client.Client) bool {
	crd := &apiextensionsv1.CustomResourceDefinition{}
	err := c.Get(ctx, types.NamespacedName{Name: "servicemonitors.monitoring.coreos.com"}, crd)
	return err == nil
}

// GetResourcesOrDefault returns the provided resource requirements if non-nil,
// otherwise returns the given default resource requirements.
func GetResourcesOrDefault(custom *corev1.ResourceRequirements, defaults corev1.ResourceRequirements) corev1.ResourceRequirements {
	if custom != nil {
		return *custom
	}
	return defaults
}

// ForEachProviderSecret iterates over the providers in the LCoreConfig and
// calls fn for each provider's credentials secret. The volume name is derived
// from the provider name as "llm-provider-<provider-name>".
func ForEachProviderSecret(cfg *LCoreConfig, fn func(secretName string, volumeName string) error) error {
	for _, provider := range cfg.Providers {
		if provider.CredentialsSecret == "" {
			continue
		}
		volumeName := "llm-provider-" + provider.Name
		if err := fn(provider.CredentialsSecret, volumeName); err != nil {
			if errors.IsNotFound(err) {
				return fmt.Errorf("provider secret %q not found: %w", provider.CredentialsSecret, err)
			}
			return err
		}
	}
	return nil
}
