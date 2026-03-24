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
	apiv1beta1 "github.com/openstack-lightspeed/operator/api/v1beta1"
)

// LCoreConfig holds the configuration needed by lcore reconciliation.
// Populated from OpenStackLightspeed CR and environment variables.
type LCoreConfig struct {
	// LLM provider config
	Providers []LCoreProvider

	// Default model and provider names
	DefaultModel    string
	DefaultProvider string

	// RAG configuration
	RAG []LCoreRAG

	// User data collection
	FeedbackDisabled    bool
	TranscriptsDisabled bool

	// System prompt
	QuerySystemPrompt string

	// TLS - additional CA configmap name (optional)
	AdditionalCAConfigMapName string

	// Labels on the owner CR (needed for exporter serviceID detection)
	OwnerLabels map[string]string
}

// LCoreProvider represents an LLM provider configuration.
type LCoreProvider struct {
	Name                string
	URL                 string
	Type                string
	CredentialsSecret   string
	Models              []LCoreModel
	AzureDeploymentName string
	APIVersion          string
	WatsonProjectID     string
}

// LCoreModel represents a model configuration.
type LCoreModel struct {
	Name                 string
	MaxTokensForResponse int
}

// LCoreRAG represents a RAG database configuration.
type LCoreRAG struct {
	Image     string
	IndexPath string
	IndexID   string
}

// BuildLCoreConfig creates an LCoreConfig from an OpenStackLightspeed instance.
func BuildLCoreConfig(instance *apiv1beta1.OpenStackLightspeed, ocpVersion string) *LCoreConfig {
	cfg := &LCoreConfig{
		DefaultModel:        instance.Spec.ModelName,
		DefaultProvider:     OpenStackLightspeedDefaultProvider,
		FeedbackDisabled:    instance.Spec.FeedbackDisabled,
		TranscriptsDisabled: instance.Spec.TranscriptsDisabled,
		QuerySystemPrompt:   GetSystemPrompt(),
		OwnerLabels:         instance.GetLabels(),
	}

	if instance.Spec.TLSCACertBundle != "" {
		cfg.AdditionalCAConfigMapName = instance.Spec.TLSCACertBundle
	}

	// Build provider
	provider := LCoreProvider{
		Name:              OpenStackLightspeedDefaultProvider,
		URL:               instance.Spec.LLMEndpoint,
		Type:              instance.Spec.LLMEndpointType,
		CredentialsSecret: instance.Spec.LLMCredentials,
		Models: []LCoreModel{
			{
				Name:                 instance.Spec.ModelName,
				MaxTokensForResponse: instance.Spec.MaxTokensForResponse,
			},
		},
		AzureDeploymentName: instance.Spec.LLMDeploymentName,
		APIVersion:          instance.Spec.LLMAPIVersion,
		WatsonProjectID:     instance.Spec.LLMProjectID,
	}
	cfg.Providers = []LCoreProvider{provider}

	// Build RAG configs
	cfg.RAG = buildLCoreRAGConfigs(instance, ocpVersion)

	return cfg
}

// buildLCoreRAGConfigs builds the RAG configuration from an OpenStackLightspeed instance.
func buildLCoreRAGConfigs(instance *apiv1beta1.OpenStackLightspeed, ocpVersion string) []LCoreRAG {
	rags := []LCoreRAG{
		{
			Image:     instance.Spec.RAGImage,
			IndexPath: OpenStackLightspeedVectorDBPath,
		},
	}

	if ocpVersion != "" {
		rags = append(rags, LCoreRAG{
			Image:     instance.Spec.RAGImage,
			IndexPath: GetOCPVectorDBPath(ocpVersion),
			IndexID:   GetOCPIndexName(ocpVersion),
		})
	}

	return rags
}
