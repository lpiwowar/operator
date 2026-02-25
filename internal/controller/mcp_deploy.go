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

	common_helper "github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	openstackv1 "github.com/openstack-k8s-operators/openstack-operator/api/core/v1beta1"
	apiv1beta1 "github.com/openstack-lightspeed/operator/api/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	openstackPodsNamespace string = "openstack"
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

	err := copySecretsConfigMaps()
	if err != nil {

	}
	// deployes MCP server

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
				Containers: []corev1.Container{{
					Name:  "mcp-server-container",
					Image: "quay.io/openstack-lightspeed/rhos-mcps:latest",
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
