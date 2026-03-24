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
	"os"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ReconcilerAdapter wraps a client.Client to implement the Reconciler interface.
type ReconcilerAdapter struct {
	client.Client
	scheme    *runtime.Scheme
	logger    logr.Logger
	namespace string
	owner     client.Object
}

// NewReconcilerAdapter creates a new ReconcilerAdapter.
func NewReconcilerAdapter(c client.Client, scheme *runtime.Scheme, logger logr.Logger, owner client.Object) *ReconcilerAdapter {
	return &ReconcilerAdapter{
		Client:    c,
		scheme:    scheme,
		logger:    logger,
		namespace: owner.GetNamespace(),
		owner:     owner,
	}
}

func (a *ReconcilerAdapter) GetScheme() *runtime.Scheme { return a.scheme }
func (a *ReconcilerAdapter) GetLogger() logr.Logger     { return a.logger }
func (a *ReconcilerAdapter) GetNamespace() string       { return a.namespace }
func (a *ReconcilerAdapter) GetOwner() client.Object    { return a.owner }

func (a *ReconcilerAdapter) GetLCoreImage() string {
	return os.Getenv("RELATED_IMAGE_LCORE")
}

func (a *ReconcilerAdapter) GetPostgresImage() string {
	return os.Getenv("RELATED_IMAGE_POSTGRES")
}

func (a *ReconcilerAdapter) GetDataverseExporterImage() string {
	return os.Getenv("RELATED_IMAGE_EXPORTER")
}

func (a *ReconcilerAdapter) IsPrometheusAvailable() bool {
	return IsPrometheusOperatorAvailable(context.Background(), a.Client)
}

func (a *ReconcilerAdapter) GetLCoreServerMode() bool {
	// TODO(lpiwowar)
	return true // library mode
}
