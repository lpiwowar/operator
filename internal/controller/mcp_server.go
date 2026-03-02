/*
Copyright 2026.

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
	"errors"
	"fmt"

	common_cm "github.com/openstack-k8s-operators/lib-common/modules/common/configmap"
	common_deployment "github.com/openstack-k8s-operators/lib-common/modules/common/deployment"
	common_helper "github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	common_secret "github.com/openstack-k8s-operators/lib-common/modules/common/secret"
	openstackv1 "github.com/openstack-k8s-operators/openstack-operator/api/core/v1beta1"
	apiv1beta1 "github.com/openstack-lightspeed/operator/api/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	// openStackConfigMapVolume is the name of the Volume section in the MCP server deployment
	// that holds the ConfigMap containing clouds.yaml.
	openStackConfigMapVolume string = "openstack-config"

	// openStackSecretVolume is the name of the Volume section in the MCP server deployment
	// that holds the Secret containing secret.yaml.
	openStackSecretVolume string = "openstack-config-secret"

	// combinedCaBundleSecretVolume is the name of the Volume section in the MCP server deployment
	// that holds the TLS CA bundle Secret.
	combinedCaBundleSecretVolume string = "combined-ca-bundle"

	// mcpConfigMapNameVolume is the name of the Volume section in the MCP server deployment
	// that holds the ConfigMap containing config.yaml for the MCP server.
	mcpConfigMapNameVolume string = "mcp-config"
)

func (r *OpenStackLightspeedReconciler) ReconcileMCPServer(
	ctx context.Context,
	helper *common_helper.Helper,
	instance *apiv1beta1.OpenStackLightspeed,
) (ctrl.Result, error) {
	ocpList := &openstackv1.OpenStackControlPlaneList{}
	err := r.List(ctx, ocpList)
	if err != nil {
		return ctrl.Result{}, err
	}

	// TODO: Create Service Account
	var OpenStackControlPlaneInstance openstackv1.OpenStackControlPlane
	if len(ocpList.Items) == 0 {
		r.GetLogger(ctx).Info("No OpenStackControlPlane found")

		deployment := getMCPServerDeployment(instance)
		err = helper.GetClient().Delete(ctx, &deployment)
		if err != nil {
			return ctrl.Result{}, err
		}

		instance.Status.Conditions.MarkTrue(
			apiv1beta1.OpenStackLightspeedMCPServerReadyCondition,
			apiv1beta1.OpenStackLightspeedMCPServerNoDeployment,
		)

		return ctrl.Result{}, nil
	} else if len(ocpList.Items) > 1 {
		err = errors.New("more than one OpenStackControlPlane found")
		r.GetLogger(ctx).Error(err, "Multiple OpenStackControlPlane resources found")
		return ctrl.Result{}, err
	} else {
		OpenStackControlPlaneInstance = ocpList.Items[0]
	}

	// Validate required fields are not nil
	if OpenStackControlPlaneInstance.Spec.OpenStackClient.Template.OpenStackConfigSecret == nil {
		err = errors.New("OpenStackClient.Template.OpenStackConfigSecret is nil")
		r.GetLogger(ctx).Error(err, "Required field is missing")
		return ctrl.Result{}, err
	}
	if OpenStackControlPlaneInstance.Spec.OpenStackClient.Template.OpenStackConfigMap == nil {
		err = errors.New("OpenStackClient.Template.OpenStackConfigMap is nil")
		r.GetLogger(ctx).Error(err, "Required field is missing")
		return ctrl.Result{}, err
	}

	// TODO: no need for instance passing twice
	secretToCopy := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      *OpenStackControlPlaneInstance.Spec.OpenStackClient.Template.OpenStackConfigSecret,
			Namespace: OpenStackControlPlaneInstance.Namespace,
		},
	}
	copySecretClouds, err := copyObjectFromNamespace(ctx, helper, secretToCopy, instance.Namespace, instance)
	if err != nil {
		return ctrl.Result{}, err
	}

	configMapToCopy := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      *OpenStackControlPlaneInstance.Spec.OpenStackClient.Template.OpenStackConfigMap,
			Namespace: OpenStackControlPlaneInstance.Namespace,
		},
	}
	copyConfigMapClouds, err := copyObjectFromNamespace(ctx, helper, configMapToCopy, instance.Namespace, instance)
	if err != nil {
		return ctrl.Result{}, err
	}

	secretToCopy = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      OpenStackControlPlaneInstance.Status.TLS.CaBundleSecretName,
			Namespace: OpenStackControlPlaneInstance.Namespace,
		},
	}
	var copyConfigMapTLSBundle crclient.Object
	copyConfigMapTLSBundle, err = copyObjectFromNamespace(ctx, helper, secretToCopy, instance.Namespace, instance)
	if err != nil {
		return ctrl.Result{}, err
	}

	// TODO: Polish this
	err = r.createConfig(ctx, helper.GetClient(), instance)
	if err != nil {
		return ctrl.Result{}, err
	}

	// TODO: Copy kubernetes secret
	svc := getMCPServerService(instance)
	_, err = controllerutil.CreateOrPatch(ctx, r.Client, &svc, func() error {
		return nil
	})
	if err != nil {
		return ctrl.Result{}, err
	}

	deployment := getMCPServerDeployment(instance)
	_, err = controllerutil.CreateOrPatch(ctx, r.Client, &deployment, func() error {
		SecretClouds := getMCPServerDeploymentVolume(deployment, openStackSecretVolume)
		SecretClouds.VolumeSource.Secret.SecretName = copySecretClouds.GetName()

		ConfigMapClouds := getMCPServerDeploymentVolume(deployment, openStackConfigMapVolume)
		ConfigMapClouds.VolumeSource.ConfigMap.LocalObjectReference.Name = copyConfigMapClouds.GetName()

		if copyConfigMapTLSBundle != nil {
			TLSBundle := getMCPServerDeploymentVolume(deployment, combinedCaBundleSecretVolume)
			TLSBundle.VolumeSource.Secret.SecretName = copyConfigMapTLSBundle.GetName()
		}

		// TODO: Do Garbage collecting of cold Config Maps
		return nil
	})

	latestDeployment := &appsv1.Deployment{}
	err = r.Client.Get(ctx, crclient.ObjectKey{
		Name:      deployment.Name,
		Namespace: deployment.Namespace,
	}, latestDeployment)
	if err != nil {
		return ctrl.Result{}, err
	}

	if common_deployment.IsReady(*latestDeployment) {
		instance.Status.Conditions.MarkTrue(
			apiv1beta1.OpenStackLightspeedMCPServerReadyCondition,
			apiv1beta1.OpenStackLightspeedMCPServerDeployed,
		)
	}

	err = garbageCollect(ctx, helper)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, err
}

func markResourceForDeletion(ctx context.Context, helper *common_helper.Helper, object crclient.Object) error {
	currentLabels := object.GetLabels()
	currentLabels["openstack-lightspeed/garbage-collect"] = "true"
	object.SetLabels(currentLabels)

	err := helper.GetClient().Update(ctx, object)
	if err != nil && k8s_errors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}

	return nil
}

func deleteMCPServer(ctx context.Context, helper common_helper.Helper, instance *apiv1beta1.OpenStackLightspeed) error {
	deployment := getMCPServerDeployment(instance)
	return helper.GetClient().Delete(ctx, &deployment)
}

// copyObjectFromNamespace copies a resource (supported types: Secret, ConfigMap) from the source
// namespace to the target namespace. The new object contains only the same data and stringData (for Secrets),
// or data and binaryData (for ConfigMaps), as the original. The name of the copied object is suffixed with
// "-copy-[hash]", where the hash is computed from the object's data and/or stringData to ensure uniqueness.
func copyObjectFromNamespace(
	ctx context.Context,
	helper *common_helper.Helper,
	object crclient.Object,
	namespace string,
	instance *apiv1beta1.OpenStackLightspeed,
) (crclient.Object, error) {
	objectKey := types.NamespacedName{
		Namespace: object.GetNamespace(),
		Name:      object.GetName(),
	}

	err := helper.GetClient().Get(ctx, objectKey, object)
	if err != nil {
		return nil, err
	}

	const hashLength = 5
	switch obj := object.(type) {
	case *corev1.Secret:
		copySecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
			},
			Data:       obj.Data,
			StringData: obj.StringData,
			Type:       obj.Type,
		}
		hash, err := common_secret.Hash(copySecret)
		if err != nil {
			return nil, err
		}

		copySecret.Name = fmt.Sprintf("%s-copy-%s", obj.Name, hash[:hashLength])
		copySecret.SetOwnerReferences([]metav1.OwnerReference{createOwnerReference(instance)})

		_, err = controllerutil.CreateOrPatch(ctx, helper.GetClient(), copySecret, func() error {
			return nil
		})
		if err != nil {
			return nil, err
		}

		err = markResourceForDeletion(ctx, helper, copySecret)
		if err != nil {
			return nil, err
		}

		return copySecret, nil

	case *corev1.ConfigMap:
		copyConfigMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
			},
			Data:       obj.Data,
			BinaryData: obj.BinaryData,
		}
		hash, err := common_cm.Hash(copyConfigMap)
		if err != nil {
			return nil, err
		}

		copyConfigMap.Name = fmt.Sprintf("%s-copy-%s", obj.Name, hash[:hashLength])
		copyConfigMap.SetOwnerReferences([]metav1.OwnerReference{createOwnerReference(instance)})

		_, err = controllerutil.CreateOrPatch(ctx, helper.GetClient(), copyConfigMap, func() error {
			return nil
		})
		if err != nil {
			return nil, err
		}

		err = markResourceForDeletion(ctx, helper, copyConfigMap)
		if err != nil {
			return nil, err
		}

		return copyConfigMap, nil

	default:
		return nil, errors.New("cannot copy k8s resource (invalid type)")
	}
}

func garbageCollect(ctx context.Context, helper *common_helper.Helper) error {
	resourcesToDelete := []crclient.ObjectList{
		&corev1.SecretList{},
		&corev1.ConfigMapList{},
	}

	selector := labels.SelectorFromSet(map[string]string{"garbage-collect": "true"})

	for _, resourceList := range resourcesToDelete {
		helper.GetClient().List(ctx, resourceList, &client.ListOptions{
			LabelSelector: selector,
		})

		objects, err := meta.ExtractList(resourceList)
		if err != nil {
			continue
		}

		for _, obj := range objects {
			object, ok := obj.(crclient.Object)
			if !ok {
				continue
			}

			err = helper.GetClient().Delete(ctx, object)
			if err != nil && !k8s_errors.IsNotFound(err) {
				return err
			}
		}
	}

	return nil
}

// createConfig creates the mcp-config ConfigMap with config.yaml key in instance.Namespace.
func (r *OpenStackLightspeedReconciler) createConfig(
	ctx context.Context,
	client crclient.Client,
	instance *apiv1beta1.OpenStackLightspeed,
) error {
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
			Name:      mcpConfigMapNameVolume,
			Namespace: instance.Namespace,
		},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, client, cm, func() error {
		if cm.Data == nil {
			cm.Data = make(map[string]string)
		}
		cm.Data["config.yaml"] = mcpConfigYAML
		cm.SetOwnerReferences([]metav1.OwnerReference{createOwnerReference(instance)})
		return nil
	})
	return err
}

func getMCPServerService(
	instance *apiv1beta1.OpenStackLightspeed,
) corev1.Service {
	mcpLabels := map[string]string{
		"app": "mcp-server",
	}

	service := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mcp-server-service",
			Namespace: instance.Namespace,
			Labels:    mcpLabels,
		},
		Spec: corev1.ServiceSpec{
			Selector: mcpLabels,
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Protocol:   corev1.ProtocolTCP,
					Port:       8080,
					TargetPort: intstr.FromInt(8080),
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}

	service.SetOwnerReferences([]metav1.OwnerReference{createOwnerReference(instance)})
	return service
}

func getMCPServerDeploymentVolume(deployment appsv1.Deployment, volumeName string) *corev1.Volume {
	for i, volume := range deployment.Spec.Template.Spec.Volumes {
		if volume.Name == volumeName {
			return &deployment.Spec.Template.Spec.Volumes[i]
		}
	}

	return nil
}

func getMCPServerDeployment(
	instance *apiv1beta1.OpenStackLightspeed,
) appsv1.Deployment {
	mcpLabels := map[string]string{
		"app": "mcp-server",
	}
	const resourceNamePlaceholder = "<name-placeholder>"

	deployment := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mcp-server",
			Namespace: instance.Namespace,
			Labels:    mcpLabels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: mcpLabels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: mcpLabels,
				},
				Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{
						{
							Name: openStackSecretVolume,
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: resourceNamePlaceholder,
									Items:      []corev1.KeyToPath{{Key: "secure.yaml", Path: "secure.yaml"}},
								},
							},
						},
						{
							Name: openStackConfigMapVolume,
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: resourceNamePlaceholder},
									Items:                []corev1.KeyToPath{{Key: "clouds.yaml", Path: "clouds.yaml"}},
								},
							},
						},
						{
							Name: combinedCaBundleSecretVolume,
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: resourceNamePlaceholder,
									Items:      []corev1.KeyToPath{{Key: "tls-ca-bundle.pem", Path: "tls-ca-bundle.pem"}},
								},
							},
						},
						{
							Name: mcpConfigMapNameVolume,
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: mcpConfigMapNameVolume},
									Items:                []corev1.KeyToPath{{Key: "config.yaml", Path: "config.yaml"}},
								},
							},
						},
					},
					Containers: []corev1.Container{{
						Name:  "mcp-server-container",
						Image: "quay.io/openstack-lightspeed/rhos-mcps:latest",
						VolumeMounts: []corev1.VolumeMount{
							{Name: openStackSecretVolume, MountPath: "/app/secure.yaml", SubPath: "secure.yaml"},
							{Name: openStackConfigMapVolume, MountPath: "/app/clouds.yaml", SubPath: "clouds.yaml"},
							{Name: combinedCaBundleSecretVolume, MountPath: "/app/tls-ca-bundle.pem", SubPath: "tls-ca-bundle.pem", ReadOnly: true},
							{Name: mcpConfigMapNameVolume, MountPath: "/app/config.yaml", SubPath: "config.yaml"},
						},
					}},
				},
			},
		},
	}

	deployment.SetOwnerReferences([]metav1.OwnerReference{createOwnerReference(instance)})
	return deployment
}
