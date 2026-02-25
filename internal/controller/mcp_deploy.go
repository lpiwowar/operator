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

	openstackv1 "github.com/openstack-k8s-operators/openstack-operator/api/core/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	openstackPodsNamespace string = "openstack"
)

func (r *OpenStackLightspeedReconciler) ReconcileMCPServer(ctx context.Context) (ctrl.Result, error) {
	instance := &openstackv1.OpenStackControlPlane{}
	err := r.Client.Get(ctx, types.NamespacedName{Name: openstackPodsNamespace}, instance)
	if err != nil {
		return ctrl.Result{}, err
	}

	cond := instance.Status.Conditions.Get(openstackv1.OpenStackControlPlaneClientReadyCondition)
	if cond == nil || cond.Status != "True" {
		return ctrl.Result{}, nil
	}

	// deployes MCP server

	// Create or update the Service for the MCP server
	mcpService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mcp-server-service",
			Namespace: "my-mcp-namespace",
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

	// Create or update the Pod for the MCP server
	mcpPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mcp-server-pod",
			Namespace: "my-mcp-namespace",
		},
	}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, mcpPod, func() error {
		mcpPod.ObjectMeta.Labels = map[string]string{"app": "mcp-server"}
		mcpPod.Spec.Containers = []corev1.Container{{
			Name:  "mcp-server-container",
			Image: "quay.io/openstack-lightspeed/rhos-mcps:latest",
		}}
		return nil
	})
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}
