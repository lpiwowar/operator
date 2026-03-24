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

import "time"

const (
	/*** Volume Permissions ***/
	VolumeDefaultMode    = int32(420)
	VolumeRestrictedMode = int32(0600)

	/*** Operator Settings ***/
	ResourceCreationTimeout = 60 * time.Second

	/*** Application Server ***/
	OLSAppServerServiceAccountName = "lightspeed-app-server"
	OLSAppServerSARRoleName        = OLSAppServerServiceAccountName + "-sar-role"
	OLSAppServerSARRoleBindingName = OLSAppServerSARRoleName + "-binding"
	OLSAppServerDeploymentName     = "lightspeed-app-server"
	OLSAppServerContainerPort      = 8443
	OLSAppServerServicePort        = 8443
	OLSAppServerServiceName        = "lightspeed-app-server"
	OLSAppServerNetworkPolicyName  = "lightspeed-app-server"
	OLSCertsSecretName             = "lightspeed-tls" // #nosec G101

	// #nosec G101
	ServingCertSecretAnnotationKey = "service.beta.openshift.io/serving-cert-secret-name"

	/*** Monitoring ***/
	AppServerServiceMonitorName                = "lightspeed-app-server-monitor"
	AppServerPrometheusRuleName                = "lightspeed-app-server-prometheus-rule"
	AppServerMetricsPath                       = "/metrics"
	MetricsReaderServiceAccountTokenSecretName = "metrics-reader-token" // #nosec G101
	MetricsReaderServiceAccountName            = "lightspeed-operator-metrics-reader"

	/*** Cert / CA ***/
	OLSAppCertsMountRoot   = "/etc/certs"
	OLSCAConfigMap         = "openshift-service-ca.crt"
	OpenShiftCAVolumeName  = "openshift-ca"
	AdditionalCAVolumeName = "additional-ca"
	AdditionalCACertFile   = "cert.crt"

	/*** Postgres ***/
	PostgresCAVolume                           = "cm-olspostgresca"
	PostgresDeploymentName                     = "lightspeed-postgres-server"
	PostgresServiceName                        = "lightspeed-postgres-server"
	PostgresSecretName                         = "lightspeed-postgres-secret"    // #nosec G101
	PostgresCertsSecretName                    = "lightspeed-postgres-certs"     // #nosec G101
	PostgresBootstrapSecretName                = "lightspeed-postgres-bootstrap" // #nosec G101
	PostgresConfigMapName                      = "lightspeed-postgres-conf"
	PostgresNetworkPolicyName                  = "lightspeed-postgres-server"
	PostgresServicePort                        = int32(5432)
	PostgresDefaultUser                        = "postgres"
	PostgresDefaultDbName                      = "postgres"
	PostgresDefaultSSLMode                     = "require"
	PostgresSharedBuffers                      = "256MB"
	PostgresMaxConnections                     = 2000
	OLSComponentPasswordFileName               = "password"
	PostgresExtensionScript                    = "create-extensions.sh"
	PostgresConfigKey                          = "postgresql.conf.sample"
	PostgresBootstrapVolumeMountPath           = "/usr/share/container-scripts/postgresql/start/create-extensions.sh"
	PostgresConfigVolumeMountPath              = "/usr/share/pgsql/postgresql.conf.sample"
	PostgresDataVolume                         = "postgres-data"
	PostgresDataVolumeMountPath                = "/var/lib/pgsql"
	PostgresVarRunVolumeName                   = "lightspeed-postgres-var-run"
	PostgresVarRunVolumeMountPath              = "/var/run/postgresql"
	TmpVolumeName                              = "tmp-writable-volume"
	TmpVolumeMountPath                         = "/tmp"
	PostgresConfigMapResourceVersionAnnotation = "ols.openshift.io/postgres-configmap-version"

	PostgresBootStrapScriptContent = `
#!/bin/bash

cat /var/lib/pgsql/data/userdata/postgresql.conf

echo "attempting to create llama-stack database and pg_trgm extension if they do not exist"

_psql () { psql --set ON_ERROR_STOP=1 "$@" ; }

# Create database for llama-stack conversation storage
DB_NAME="` + LlamaStackDatabaseName + `"

echo "SELECT 'CREATE DATABASE $DB_NAME' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$DB_NAME')\gexec" | _psql -d $POSTGRESQL_DATABASE

# Create pg_trgm extension in default database (for OLS conversation cache)
echo "CREATE EXTENSION IF NOT EXISTS pg_trgm;" | _psql -d $POSTGRESQL_DATABASE

# Create pg_trgm extension in llama-stack database (for text search if needed)
echo "CREATE EXTENSION IF NOT EXISTS pg_trgm;" | _psql -d $DB_NAME

# Create schemas for isolating different components' data
echo "CREATE SCHEMA IF NOT EXISTS lcore;" | _psql -d $POSTGRESQL_DATABASE
echo "CREATE SCHEMA IF NOT EXISTS quota;" | _psql -d $POSTGRESQL_DATABASE
echo "CREATE SCHEMA IF NOT EXISTS conversation_cache;" | _psql -d $POSTGRESQL_DATABASE
`

	PostgresConfigMapContent = `
huge_pages = off
ssl = on
ssl_cert_file = '/etc/certs/tls.crt'
ssl_key_file = '/etc/certs/tls.key'
ssl_ca_file = '/etc/certs/cm-olspostgresca/service-ca.crt'
`

	/*** LCore specific ***/
	LlamaStackConfigCmName                       = "llama-stack-config"
	LCoreConfigCmName                            = "lightspeed-stack-config"
	LCoreDeploymentName                          = "lightspeed-stack-deployment"
	LlamaStackConfigMountPath                    = "/app-root/run.yaml"
	LCoreConfigMountPath                         = "/app-root/lightspeed-stack.yaml"
	LlamaStackConfigFilename                     = "run.yaml"
	LCoreConfigFilename                          = "lightspeed-stack.yaml"
	LCoreConfigMapResourceVersionAnnotation      = "ols.openshift.io/lcore-configmap-version"
	LlamaStackConfigMapResourceVersionAnnotation = "ols.openshift.io/llamastack-configmap-version"
	LlamaStackDatabaseName                       = "llamastack"
	LCoreUserDataMountPath                       = "/tmp/data"
	ForceReloadAnnotationKey                     = "ols.openshift.io/force-reload"

	/*** Data Exporter ***/
	ExporterConfigCmName        = "lightspeed-exporter-config"
	ExporterConfigVolumeName    = "exporter-config"
	ExporterConfigMountPath     = "/etc/config"
	ExporterConfigFilename      = "config.yaml"
	ServiceIDOLS                = "ols"
	RHOSOLightspeedOwnerIDLabel = "openstack.org/lightspeed-owner-id"
	ServiceIDRHOSO              = "rhos-lightspeed"

	/*** Azure ***/
	AzureOpenAIType = "azure_openai"
)
