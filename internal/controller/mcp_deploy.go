/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	p://www.apache.org/licenses/LICENSE-2.0

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

	common_helper "github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	openstackv1 "github.com/openstack-k8s-operators/openstack-operator/api/core/v1beta1"
	apiv1beta1 "github.com/openstack-lightspeed/operator/api/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	openstackPodsNamespace     string = "openstack"
	openstackConfigMapName     string = "openstack-config"
	openstackSecretName        string = "openstack-config-secret"
	combinedCaBundleSecretName string = "combined-ca-bundle"
	mcpConfigMapName           string = "mcp-config"
)

func (r *OpenStackLightspeedReconciler) ReconcileMCPServer(
	ctx context.Context,
	helper *common_helper.Helper,
	instance *apiv1beta1.OpenStackLightspeed,
) (ctrl.Result, error) {
	// instance := &openstackv1.OpenStackControlPlane{}
	client, err := GetRawClient(helper)
	if err != nil {
		return ctrl.Result{}, err
	}

	// List all OpenStackControlPlane resources in the openstack namespace
	ocpList := &openstackv1.OpenStackControlPlaneList{}
	err = client.List(ctx, ocpList, crclient.InNamespace(openstackPodsNamespace))
	if err != nil {
		return ctrl.Result{}, err
	}

	cond := ocpList.Items[0].Status.Conditions.Get(openstackv1.OpenStackControlPlaneClientReadyCondition)
	if cond == nil || cond.Status != "True" {
		return ctrl.Result{}, nil
	}

	if err = r.copySecretsConfigMaps(ctx, client, instance); err != nil {
		return ctrl.Result{}, err
	}
	if err = r.createConfig(ctx, client, instance); err != nil {
		return ctrl.Result{}, err
	}
	// deploy MCP server

	// Create or update the Service for the MCP server
	mcpService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mcp-server-service",
			Namespace: instance.Namespace,
		},
	}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, mcpService, func() error {
		mcpService.Spec.Selector = map[string]string{
			"app": "mcp-server",
		}
		mcpService.Spec.Ports = []corev1.ServicePort{{
			Protocol:   corev1.ProtocolTCP,
			Port:       8080,
			TargetPort: intstr.FromInt(8080),
		}}
		return nil
	})
	if err != nil {
		return ctrl.Result{}, err
	}

	// Create or update the Deployment for the MCP server (Deployment allows Pod template
	// changes without hitting Pod immutability; the controller rolls out new Pods).
	mcpDeploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mcp-server",
			Namespace: instance.Namespace,
		},
	}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, mcpDeploy, func() error {
		mcpDeploy.ObjectMeta.Labels = map[string]string{"app": "mcp-server"}
		one := int32(1)
		mcpDeploy.Spec.Replicas = &one
		mcpDeploy.Spec.Selector = &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "mcp-server"},
		}
		mcpDeploy.Spec.Template = corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{"app": "mcp-server"},
			},
			Spec: corev1.PodSpec{
				Volumes: []corev1.Volume{
					{
						Name: openstackSecretName,
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName: openstackSecretName,
								Items: []corev1.KeyToPath{{
									Key:  "secure.yaml",
									Path: "secure.yaml",
								}},
							},
						},
					},
					{
						Name: openstackConfigMapName,
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{Name: openstackConfigMapName},
								Items: []corev1.KeyToPath{{
									Key:  "clouds.yaml",
									Path: "clouds.yaml",
								}},
							},
						},
					},
					{
						Name: combinedCaBundleSecretName,
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName: combinedCaBundleSecretName,
								Items: []corev1.KeyToPath{{
									Key:  "tls-ca-bundle.pem",
									Path: "tls-ca-bundle.pem",
								}},
							},
						},
					},
					{
						Name: mcpConfigMapName,
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{Name: mcpConfigMapName},
								Items: []corev1.KeyToPath{{
									Key:  "config.yaml",
									Path: "config.yaml",
								}},
							},
						},
					},
				},
				Containers: []corev1.Container{{
					Name:  "mcp-server-container",
					Image: "quay.io/openstack-lightspeed/rhos-mcps:latest",
					VolumeMounts: []corev1.VolumeMount{
						{Name: openstackSecretName, MountPath: "/app/secure.yaml", SubPath: "secure.yaml"},
						{Name: openstackConfigMapName, MountPath: "/app/clouds.yaml", SubPath: "clouds.yaml"},
						{Name: combinedCaBundleSecretName, MountPath: "/app/tls-ca-bundle.pem", SubPath: "tls-ca-bundle.pem", ReadOnly: true},
						{Name: mcpConfigMapName, MountPath: "/app/config.yaml", SubPath: "config.yaml"},
					},
				}},
			},
		}
		return nil
	})
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// copySecretsConfigMaps copies the openstack-config ConfigMap, openstack-config-secret,
// and combined-ca-bundle Secret from the openstack namespace into instance.Namespace so the MCP server can use them.
func (r *OpenStackLightspeedReconciler) copySecretsConfigMaps(
	ctx context.Context,
	client crclient.Client,
	instance *apiv1beta1.OpenStackLightspeed,
) error {
	ownerRef := metav1.OwnerReference{
		APIVersion:         instance.APIVersion,
		Kind:               instance.Kind,
		Name:               instance.GetName(),
		UID:                instance.GetUID(),
		Controller:         ptr.To(true),
		BlockOwnerDeletion: ptr.To(true),
	}

	// Copy ConfigMap openstack-config
	srcCM := &corev1.ConfigMap{}
	if err := client.Get(ctx, types.NamespacedName{Namespace: openstackPodsNamespace, Name: openstackConfigMapName}, srcCM); err != nil {
		if k8s_errors.IsNotFound(err) {
			return fmt.Errorf("configmap %s/%s not found: %w", openstackPodsNamespace, openstackConfigMapName, err)
		}
		return err
	}
	destCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      openstackConfigMapName,
			Namespace: instance.Namespace,
		},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, client, destCM, func() error {
		destCM.Data = make(map[string]string)
		for k, v := range srcCM.Data {
			destCM.Data[k] = v
		}
		destCM.BinaryData = make(map[string][]byte)
		for k, v := range srcCM.BinaryData {
			destCM.BinaryData[k] = v
		}
		destCM.SetOwnerReferences([]metav1.OwnerReference{ownerRef})
		return nil
	})
	if err != nil {
		return err
	}

	// Copy Secret openstack-config-secret
	srcSecret := &corev1.Secret{}
	if err := client.Get(ctx, types.NamespacedName{Namespace: openstackPodsNamespace, Name: openstackSecretName}, srcSecret); err != nil {
		if k8s_errors.IsNotFound(err) {
			return fmt.Errorf("secret %s/%s not found: %w", openstackPodsNamespace, openstackSecretName, err)
		}
		return err
	}
	destSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      openstackSecretName,
			Namespace: instance.Namespace,
		},
	}
	_, err = controllerutil.CreateOrUpdate(ctx, client, destSecret, func() error {
		destSecret.Data = make(map[string][]byte)
		for k, v := range srcSecret.Data {
			destSecret.Data[k] = v
		}
		destSecret.Type = srcSecret.Type
		destSecret.SetOwnerReferences([]metav1.OwnerReference{ownerRef})
		return nil
	})
	if err != nil {
		return err
	}

	// Copy Secret combined-ca-bundle
	srcCaBundle := &corev1.Secret{}
	if err := client.Get(ctx, types.NamespacedName{Namespace: openstackPodsNamespace, Name: combinedCaBundleSecretName}, srcCaBundle); err != nil {
		if k8s_errors.IsNotFound(err) {
			return fmt.Errorf("secret %s/%s not found: %w", openstackPodsNamespace, combinedCaBundleSecretName, err)
		}
		return err
	}
	destCaBundle := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      combinedCaBundleSecretName,
			Namespace: instance.Namespace,
		},
	}
	_, err = controllerutil.CreateOrUpdate(ctx, client, destCaBundle, func() error {
		destCaBundle.Data = make(map[string][]byte)
		for k, v := range srcCaBundle.Data {
			destCaBundle.Data[k] = v
		}
		destCaBundle.Type = srcCaBundle.Type
		destCaBundle.SetOwnerReferences([]metav1.OwnerReference{ownerRef})
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// createConfig creates the mcp-config ConfigMap with config.yaml key in instance.Namespace.
func (r *OpenStackLightspeedReconciler) createConfig(
	ctx context.Context,
	client crclient.Client,
	instance *apiv1beta1.OpenStackLightspeed,
) error {
	ownerRef := metav1.OwnerReference{
		APIVersion:         instance.APIVersion,
		Kind:               instance.Kind,
		Name:               instance.GetName(),
		UID:                instance.GetUID(),
		Controller:         ptr.To(true),
		BlockOwnerDeletion: ptr.To(true),
	}

	mcpConfigYAML := `ip: 0.0.0.0
port: 8080
debug: true
workers: 1
processes_pool_size: 10

openstack:
  allow_write: false
  ca_cert: ./tls-ca-bundle.pem
  insecure: false

openshift:
  allow_write: false
  insecure: false

mcp_transport_security:
    # token: supersecret
    enable_dns_rebinding_protection: false
    allowed_hosts:
      - "*:*"
    allowed_origins:
      - "http://*:*"
`

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      mcpConfigMapName,
			Namespace: instance.Namespace,
		},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, client, cm, func() error {
		if cm.Data == nil {
			cm.Data = make(map[string]string)
		}
		cm.Data["config.yaml"] = mcpConfigYAML
		cm.SetOwnerReferences([]metav1.OwnerReference{ownerRef})
		return nil
	})
	return err
}
