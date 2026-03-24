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
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Reconciler interface defines the contract that lcore reconciliation code needs.
type Reconciler interface {
	client.Client

	// GetScheme returns the Kubernetes scheme
	GetScheme() *runtime.Scheme

	// GetLogger returns the logger instance
	GetLogger() logr.Logger

	// GetNamespace returns the operator's namespace
	GetNamespace() string

	// GetOwner returns the owner object for SetControllerReference
	GetOwner() client.Object

	// GetLCoreImage returns the LCore container image
	GetLCoreImage() string

	// GetPostgresImage returns the Postgres container image
	GetPostgresImage() string

	// GetDataverseExporterImage returns the data exporter container image
	GetDataverseExporterImage() string

	// IsPrometheusAvailable returns whether Prometheus Operator CRDs are available
	IsPrometheusAvailable() bool

	// GetLCoreServerMode returns whether LCore should run in server mode (true) or library mode (false)
	GetLCoreServerMode() bool
}
