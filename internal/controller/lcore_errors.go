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

const (
	ErrCreateAPIConfigmap             = "failed to create OLS configmap"
	ErrCreateAPIDeployment            = "failed to create OLS deployment"
	ErrCreateAPIService               = "failed to create OLS service"
	ErrCreateAPIServiceAccount        = "failed to create OLS service account"
	ErrCreateAppServerNetworkPolicy   = "failed to create AppServer network policy"
	ErrCreateSARClusterRole           = "failed to create SAR cluster role"
	ErrCreateSARClusterRoleBinding    = "failed to create SAR cluster role binding"
	ErrCreateServiceMonitor           = "failed to create ServiceMonitor"
	ErrCreateMetricsReaderSecret      = "failed to create metrics reader secret"
	ErrCreatePrometheusRule           = "failed to create PrometheusRule"
	ErrGenerateAPIConfigmap           = "failed to generate OLS configmap"
	ErrGenerateAPIDeployment          = "failed to generate OLS deployment"
	ErrGenerateAPIService             = "failed to generate OLS service"
	ErrGenerateAPIServiceAccount      = "failed to generate OLS service account"
	ErrGenerateAppServerNetworkPolicy = "failed to generate AppServer network policy"
	ErrGenerateSARClusterRole         = "failed to generate SAR cluster role"
	ErrGenerateSARClusterRoleBinding  = "failed to generate SAR cluster role binding"
	ErrGenerateServiceMonitor         = "failed to generate ServiceMonitor"
	ErrGenerateMetricsReaderSecret    = "failed to generate metrics reader secret"
	ErrGeneratePrometheusRule         = "failed to generate PrometheusRule"
	ErrGetAdditionalCACM              = "failed to get additional CA configmap"
	ErrGetProxyCACM                   = "failed to get proxy CA configmap"
	ErrGetAPIConfigmap                = "failed to get OLS configmap"
	ErrGetAPIDeployment               = "failed to get OLS deployment"
	ErrGetAPIService                  = "failed to get OLS service"
	ErrGetAPIServiceAccount           = "failed to get OLS service account"
	ErrGetAppServerNetworkPolicy      = "failed to get AppServer network policy"
	ErrGetTLSSecret                   = "failed to get TLS secret" // #nosec G101
	ErrGetSARClusterRole              = "failed to get SAR cluster role"
	ErrGetSARClusterRoleBinding       = "failed to get SAR cluster role binding"
	ErrGetServiceMonitor              = "failed to get ServiceMonitor"
	ErrGetMetricsReaderSecret         = "failed to get metrics reader secret"
	ErrGetPrometheusRule              = "failed to get PrometheusRule"
	ErrUpdateAPIConfigmap             = "failed to update OLS configmap"
	ErrUpdateAPIDeployment            = "failed to update OLS deployment"
	ErrUpdateAPIService               = "failed to update OLS service"
	ErrUpdateAppServerNetworkPolicy   = "failed to update AppServer network policy"
	ErrUpdateProxyCACM                = "failed to update proxy CA configmap"
	ErrUpdateServiceMonitor           = "failed to update ServiceMonitor"
	ErrUpdateMetricsReaderSecret      = "failed to update metrics reader secret"
	ErrUpdatePrometheusRule           = "failed to update PrometheusRule"

	ErrCreateLlamaStackConfigMap   = "failed to create Llama Stack configmap"
	ErrGenerateLlamaStackConfigMap = "failed to generate Llama Stack configmap"
	ErrGetLlamaStackConfigMap      = "failed to get Llama Stack configmap"
	ErrUpdateLlamaStackConfigMap   = "failed to update Llama Stack configmap"

	/*** Postgres Errors ***/
	ErrGeneratePostgresDeployment      = "failed to generate Postgres deployment"
	ErrCreatePostgresDeployment        = "failed to create Postgres deployment"
	ErrGetPostgresDeployment           = "failed to get Postgres deployment"
	ErrUpdatePostgresDeployment        = "failed to update Postgres deployment"
	ErrGeneratePostgresService         = "failed to generate Postgres service"
	ErrCreatePostgresService           = "failed to create Postgres service"
	ErrGetPostgresService              = "failed to get Postgres service"
	ErrGeneratePostgresSecret          = "failed to generate Postgres secret"           // #nosec G101
	ErrCreatePostgresSecret            = "failed to create Postgres secret"             // #nosec G101
	ErrGetPostgresSecret               = "failed to get Postgres secret"                // #nosec G101
	ErrUpdatePostgresSecret            = "failed to update Postgres secret"             // #nosec G101
	ErrGeneratePostgresBootstrapSecret = "failed to generate Postgres bootstrap secret" // #nosec G101
	ErrCreatePostgresBootstrapSecret   = "failed to create Postgres bootstrap secret"   // #nosec G101
	ErrGetPostgresBootstrapSecret      = "failed to get Postgres bootstrap secret"      // #nosec G101
	ErrGeneratePostgresConfigMap       = "failed to generate Postgres configmap"
	ErrCreatePostgresConfigMap         = "failed to create Postgres configmap"
	ErrGetPostgresConfigMap            = "failed to get Postgres configmap"
	ErrGeneratePostgresNetworkPolicy   = "failed to generate Postgres network policy"
	ErrCreatePostgresNetworkPolicy     = "failed to create Postgres network policy"
	ErrGetPostgresNetworkPolicy        = "failed to get Postgres network policy"
	ErrUpdatePostgresNetworkPolicy     = "failed to update Postgres network policy"
)
