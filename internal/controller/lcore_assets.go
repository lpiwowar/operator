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

	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// GenerateServiceAccount generates the service account for the OLS app server.
func GenerateServiceAccount(r Reconciler, cfg *LCoreConfig) (*corev1.ServiceAccount, error) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      OLSAppServerServiceAccountName,
			Namespace: r.GetNamespace(),
			Labels:    GenerateAppServerSelectorLabels(),
		},
	}

	if err := controllerutil.SetControllerReference(r.GetOwner(), sa, r.GetScheme()); err != nil {
		return nil, err
	}

	return sa, nil
}

// GenerateSARClusterRole generates the SAR cluster role for authentication.
func GenerateSARClusterRole(r Reconciler, cfg *LCoreConfig) (*rbacv1.ClusterRole, error) {
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:   OLSAppServerSARRoleName,
			Labels: GenerateAppServerSelectorLabels(),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
		},
	}

	return role, nil
}

// generateSARClusterRoleBinding generates the SAR cluster role binding.
func generateSARClusterRoleBinding(r Reconciler, cfg *LCoreConfig) (*rbacv1.ClusterRoleBinding, error) {
	rb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   OLSAppServerSARRoleBindingName,
			Labels: GenerateAppServerSelectorLabels(),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      OLSAppServerServiceAccountName,
				Namespace: r.GetNamespace(),
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     OLSAppServerSARRoleName,
		},
	}

	return rb, nil
}

// GenerateService generates the service for the OLS app server.
// Always uses service-ca annotation for TLS (no custom TLS support).
func GenerateService(r Reconciler, cfg *LCoreConfig) (*corev1.Service, error) {
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      OLSAppServerServiceName,
			Namespace: r.GetNamespace(),
			Labels:    GenerateAppServerSelectorLabels(),
			Annotations: map[string]string{
				ServingCertSecretAnnotationKey: OLSCertsSecretName,
			},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:       "https",
					Port:       OLSAppServerServicePort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt32(OLSAppServerContainerPort),
				},
			},
			Selector: GenerateAppServerSelectorLabels(),
		},
	}

	if err := controllerutil.SetControllerReference(r.GetOwner(), service, r.GetScheme()); err != nil {
		return nil, err
	}

	return service, nil
}

// GenerateServiceMonitor generates the ServiceMonitor for the OLS app server.
func GenerateServiceMonitor(r Reconciler, cfg *LCoreConfig) (*monv1.ServiceMonitor, error) {
	metaLabels := GenerateAppServerSelectorLabels()
	metaLabels["monitoring.openshift.io/collection-profile"] = "full"
	metaLabels["app.kubernetes.io/component"] = "metrics"
	metaLabels["openshift.io/user-monitoring"] = "true"

	valFalse := false
	serverName := OLSAppServerServiceName + "." + r.GetNamespace() + ".svc"
	schemeHTTPS := monv1.Scheme("https")

	sm := &monv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      AppServerServiceMonitorName,
			Namespace: r.GetNamespace(),
			Labels:    metaLabels,
		},
		Spec: monv1.ServiceMonitorSpec{
			Endpoints: []monv1.Endpoint{
				{
					Port:     "https",
					Path:     AppServerMetricsPath,
					Interval: "30s",
					Scheme:   &schemeHTTPS,
					HTTPConfigWithProxyAndTLSFiles: monv1.HTTPConfigWithProxyAndTLSFiles{
						HTTPConfigWithTLSFiles: monv1.HTTPConfigWithTLSFiles{
							TLSConfig: &monv1.TLSConfig{
								TLSFilesConfig: monv1.TLSFilesConfig{
									CAFile:   "/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt",
									CertFile: "/etc/prometheus/secrets/metrics-client-certs/tls.crt",
									KeyFile:  "/etc/prometheus/secrets/metrics-client-certs/tls.key",
								},
								SafeTLSConfig: monv1.SafeTLSConfig{
									InsecureSkipVerify: &valFalse,
									ServerName:         &serverName,
								},
							},
							HTTPConfigWithoutTLS: monv1.HTTPConfigWithoutTLS{
								Authorization: &monv1.SafeAuthorization{
									Type: "Bearer",
									Credentials: &corev1.SecretKeySelector{
										Key: "token",
										LocalObjectReference: corev1.LocalObjectReference{
											Name: MetricsReaderServiceAccountTokenSecretName,
										},
									},
								},
							},
						},
					},
				},
			},
			JobLabel: "app.kubernetes.io/name",
			Selector: metav1.LabelSelector{
				MatchLabels: GenerateAppServerSelectorLabels(),
			},
		},
	}

	if err := controllerutil.SetControllerReference(r.GetOwner(), sm, r.GetScheme()); err != nil {
		return nil, err
	}

	return sm, nil
}

// GeneratePrometheusRule generates the PrometheusRule for the OLS app server.
func GeneratePrometheusRule(r Reconciler, cfg *LCoreConfig) (*monv1.PrometheusRule, error) {
	metaLabels := GenerateAppServerSelectorLabels()
	metaLabels["app.kubernetes.io/component"] = "metrics"

	rule := &monv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      AppServerPrometheusRuleName,
			Namespace: r.GetNamespace(),
			Labels:    metaLabels,
		},
		Spec: monv1.PrometheusRuleSpec{
			Groups: []monv1.RuleGroup{
				{
					Name: "ols.operations.rules",
					Rules: []monv1.Rule{
						{
							Record: "ols:rest_api_query_calls_total:2xx",
							Expr:   intstr.FromString("sum by(status_code) (ols_rest_api_calls_total{path=\"/v1/streaming_query\",status_code=~\"2..\"})"),
							Labels: map[string]string{"status_code": "2xx"},
						},
						{
							Record: "ols:rest_api_query_calls_total:4xx",
							Expr:   intstr.FromString("sum by(status_code) (ols_rest_api_calls_total{path=\"/v1/streaming_query\",status_code=~\"4..\"})"),
							Labels: map[string]string{"status_code": "4xx"},
						},
						{
							Record: "ols:rest_api_query_calls_total:5xx",
							Expr:   intstr.FromString("sum by(status_code) (ols_rest_api_calls_total{path=\"/v1/streaming_query\",status_code=~\"5..\"})"),
							Labels: map[string]string{"status_code": "5xx"},
						},
						{
							Record: "ols:provider_model_configuration",
							Expr:   intstr.FromString("max by (provider,model) (ols_provider_model_configuration)"),
						},
					},
				},
			},
		},
	}

	if err := controllerutil.SetControllerReference(r.GetOwner(), rule, r.GetScheme()); err != nil {
		return nil, err
	}

	return rule, nil
}

// GenerateAppServerNetworkPolicy generates the network policy for the OLS app server.
func GenerateAppServerNetworkPolicy(r Reconciler, cfg *LCoreConfig) (*networkingv1.NetworkPolicy, error) {
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      OLSAppServerNetworkPolicyName,
			Namespace: r.GetNamespace(),
			Labels:    GenerateAppServerSelectorLabels(),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: GenerateAppServerSelectorLabels(),
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: toPtr(corev1.ProtocolTCP),
							Port:     toPtr(intstr.FromInt32(OLSAppServerContainerPort)),
						},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}

	if err := controllerutil.SetControllerReference(r.GetOwner(), np, r.GetScheme()); err != nil {
		return nil, err
	}

	return np, nil
}

// GenerateMetricsReaderSecret generates the secret for the metrics reader service account token.
func GenerateMetricsReaderSecret(r Reconciler, cfg *LCoreConfig) (*corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      MetricsReaderServiceAccountTokenSecretName,
			Namespace: r.GetNamespace(),
			Labels:    GenerateAppServerSelectorLabels(),
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": MetricsReaderServiceAccountName,
			},
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}

	if err := controllerutil.SetControllerReference(r.GetOwner(), secret, r.GetScheme()); err != nil {
		return nil, err
	}

	return secret, nil
}

// GenerateLlamaStackConfigMap generates the ConfigMap for the Llama Stack configuration.
func GenerateLlamaStackConfigMap(r Reconciler, ctx context.Context, cfg *LCoreConfig) (*corev1.ConfigMap, error) {
	yamlData, err := buildLlamaStackYAML(r, ctx, cfg)
	if err != nil {
		return nil, err
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      LlamaStackConfigCmName,
			Namespace: r.GetNamespace(),
			Labels:    GenerateAppServerSelectorLabels(),
		},
		Data: map[string]string{
			LlamaStackConfigFilename: yamlData,
		},
	}

	if err := controllerutil.SetControllerReference(r.GetOwner(), cm, r.GetScheme()); err != nil {
		return nil, err
	}

	return cm, nil
}

// GenerateLcoreConfigMap generates the ConfigMap for the LCore configuration.
func GenerateLcoreConfigMap(r Reconciler, ctx context.Context, cfg *LCoreConfig) (*corev1.ConfigMap, error) {
	yamlData, err := buildLCoreConfigYAML(r, cfg)
	if err != nil {
		return nil, err
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      LCoreConfigCmName,
			Namespace: r.GetNamespace(),
			Labels:    GenerateAppServerSelectorLabels(),
		},
		Data: map[string]string{
			LCoreConfigFilename: yamlData,
		},
	}

	if err := controllerutil.SetControllerReference(r.GetOwner(), cm, r.GetScheme()); err != nil {
		return nil, err
	}

	return cm, nil
}

// generateExporterConfigMap generates the ConfigMap for the data exporter configuration.
func generateExporterConfigMap(r Reconciler, cfg *LCoreConfig) (*corev1.ConfigMap, error) {
	// Determine serviceID based on owner labels
	serviceID := ServiceIDOLS
	if cfg.OwnerLabels != nil {
		if _, ok := cfg.OwnerLabels[RHOSOLightspeedOwnerIDLabel]; ok {
			serviceID = ServiceIDRHOSO
		}
	}

	configData := fmt.Sprintf("service_id: %s\n", serviceID)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ExporterConfigCmName,
			Namespace: r.GetNamespace(),
			Labels:    GenerateAppServerSelectorLabels(),
		},
		Data: map[string]string{
			ExporterConfigFilename: configData,
		},
	}

	if err := controllerutil.SetControllerReference(r.GetOwner(), cm, r.GetScheme()); err != nil {
		return nil, err
	}

	return cm, nil
}

// ptr returns a pointer to the given value.
func toPtr[T any](v T) *T {
	return &v
}
