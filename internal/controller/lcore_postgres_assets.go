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
	"crypto/rand"
	"encoding/base64"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// GeneratePostgresService generates the Postgres Service object with
// the serving-cert annotation for automatic TLS certificate provisioning.
func GeneratePostgresService(r Reconciler) (*corev1.Service, error) {
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PostgresServiceName,
			Namespace: r.GetNamespace(),
			Labels:    GeneratePostgresSelectorLabels(),
			Annotations: map[string]string{
				ServingCertSecretAnnotationKey: PostgresCertsSecretName,
			},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       PostgresServicePort,
					Protocol:   corev1.ProtocolTCP,
					Name:       "server",
					TargetPort: intstr.Parse("server"),
				},
			},
			Selector: GeneratePostgresSelectorLabels(),
			Type:     corev1.ServiceTypeClusterIP,
		},
	}

	if err := controllerutil.SetControllerReference(r.GetOwner(), service, r.GetScheme()); err != nil {
		return nil, err
	}

	return service, nil
}

// GeneratePostgresSecret generates the Postgres password Secret with a random password.
func GeneratePostgresSecret(r Reconciler) (*corev1.Secret, error) {
	randomPassword := make([]byte, 12)
	_, err := rand.Read(randomPassword)
	if err != nil {
		return nil, fmt.Errorf("error generating random password: %w", err)
	}
	encodedPassword := base64.StdEncoding.EncodeToString(randomPassword)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PostgresSecretName,
			Namespace: r.GetNamespace(),
			Labels:    GeneratePostgresSelectorLabels(),
		},
		Data: map[string][]byte{
			OLSComponentPasswordFileName: []byte(encodedPassword),
		},
	}

	if err := controllerutil.SetControllerReference(r.GetOwner(), secret, r.GetScheme()); err != nil {
		return nil, err
	}

	return secret, nil
}

// GeneratePostgresBootstrapSecret generates the bootstrap script Secret
// that initializes the Postgres database with required extensions and schemas.
func GeneratePostgresBootstrapSecret(r Reconciler) (*corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PostgresBootstrapSecretName,
			Namespace: r.GetNamespace(),
			Labels:    GeneratePostgresSelectorLabels(),
		},
		StringData: map[string]string{
			PostgresExtensionScript: PostgresBootStrapScriptContent,
		},
	}

	if err := controllerutil.SetControllerReference(r.GetOwner(), secret, r.GetScheme()); err != nil {
		return nil, err
	}

	return secret, nil
}

// GeneratePostgresConfigMap generates the Postgres configuration ConfigMap
// with SSL/TLS settings.
func GeneratePostgresConfigMap(r Reconciler) (*corev1.ConfigMap, error) {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PostgresConfigMapName,
			Namespace: r.GetNamespace(),
			Labels:    GeneratePostgresSelectorLabels(),
		},
		Data: map[string]string{
			PostgresConfigKey: PostgresConfigMapContent,
		},
	}

	if err := controllerutil.SetControllerReference(r.GetOwner(), configMap, r.GetScheme()); err != nil {
		return nil, err
	}

	return configMap, nil
}

// GeneratePostgresNetworkPolicy generates the NetworkPolicy that restricts
// ingress to the Postgres pod to only allow traffic from app server pods.
func GeneratePostgresNetworkPolicy(r Reconciler) (*networkingv1.NetworkPolicy, error) {
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PostgresNetworkPolicyName,
			Namespace: r.GetNamespace(),
			Labels:    GeneratePostgresSelectorLabels(),
		},
		Spec: networkingv1.NetworkPolicySpec{
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: GenerateAppServerSelectorLabels(),
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
							Port:     &[]intstr.IntOrString{intstr.FromInt32(PostgresServicePort)}[0],
						},
					},
				},
			},
			PodSelector: metav1.LabelSelector{
				MatchLabels: GeneratePostgresSelectorLabels(),
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
