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

	_ "embed"

	"github.com/go-logr/logr"
	common_helper "github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	rbacv1 "k8s.io/api/rbac/v1"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

const (
	// OpenStackLightspeedDefaultProvider - contains default name for the provider created by the operator.
	OpenStackLightspeedDefaultProvider = "openstack-lightspeed-provider"

	// OpenStackLightspeedOwnerIDLabel - name of a label that contains ID of OpenStackLightspeed instance.
	OpenStackLightspeedOwnerIDLabel = "openstack.org/lightspeed-owner-id"

	// OpenStackLightspeedVectorDBPath - path inside of the container image where the vector DB are located.
	OpenStackLightspeedVectorDBPath = "/rag/vector_db/os_product_docs"
)

// systemPrompt - system prompt tailored to the needs of OpenStack Lightspeed.
//
//go:embed system_prompt.txt
var systemPrompt string

// GetSystemPrompt returns the OpenStackLightspeed system prompt
func GetSystemPrompt() string {
	return systemPrompt
}

// GetRawClient returns a raw client that is not restricted to WATCH_NAMESPACE.
func GetRawClient(helper *common_helper.Helper) (client.Client, error) {
	cfg, err := config.GetConfig()
	if err != nil {
		return nil, err
	}

	rawClient, err := client.New(cfg, client.Options{Scheme: helper.GetScheme()})
	if err != nil {
		return nil, err
	}

	return rawClient, nil
}

// cleanupClusterScopedResources removes cluster-scoped resources (ClusterRole, ClusterRoleBinding)
// that are not automatically garbage-collected via namespace-scoped owner references.
func cleanupClusterScopedResources(ctx context.Context, c client.Client, log logr.Logger) error {
	// Delete ClusterRoleBinding
	crb := &rbacv1.ClusterRoleBinding{}
	if err := c.Get(ctx, client.ObjectKey{Name: OLSAppServerSARRoleBindingName}, crb); err == nil {
		if err := c.Delete(ctx, crb); err != nil && !k8s_errors.IsNotFound(err) {
			return err
		}
		log.Info("Deleted ClusterRoleBinding", "name", OLSAppServerSARRoleBindingName)
	}

	// Delete ClusterRole
	cr := &rbacv1.ClusterRole{}
	if err := c.Get(ctx, client.ObjectKey{Name: OLSAppServerSARRoleName}, cr); err == nil {
		if err := c.Delete(ctx, cr); err != nil && !k8s_errors.IsNotFound(err) {
			return err
		}
		log.Info("Deleted ClusterRole", "name", OLSAppServerSARRoleName)
	}

	return nil
}
