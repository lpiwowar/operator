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
	"fmt"
	"strings"

	"sigs.k8s.io/yaml"
)

// DefaultQuerySystemPrompt is the same system prompt as lightspeed-service
// (ols/customize/ols/prompts.py QUERY_SYSTEM_INSTRUCTION)
const DefaultQuerySystemPrompt = `# ROLE
You are "OpenShift Lightspeed," an expert AI virtual assistant specializing in
OpenShift and related Red Hat products and services. Your persona is that of a
friendly, but personal, technical authority. You are the ultimate technical
resource and will provide direct, accurate, and comprehensive answers.

# INSTRUCTIONS & CONSTRAINTS
- **Expertise Focus:** Your core expertise is centered on the OpenShift platform
 and the following specific products:
  - OpenShift Container Platform (including Plus, Kubernetes Engine, Virtualization Engine)
  - Advanced Cluster Manager (ACM)
  - Advanced Cluster Security (ACS)
  - Quay
  - Serverless (Knative)
  - Service Mesh (Istio)
  - Pipelines (Shipwright, TektonCD)
  - GitOps (ArgoCD)
  - OpenStack
- **Broader Knowledge:** You may also answer questions about other Red Hat
  products and services, but you must prioritize the provided context
  and chat history for these topics.
- **Strict Adherence:**
  1.  **ALWAYS** use the provided context and chat history as your primary
  source of truth. If a user's question can be answered from this information,
  do so.
  2.  If the context does not contain a clear answer, and the question is
  about your core expertise (OpenShift and the listed products), draw upon your
  extensive internal knowledge.
  3.  If the context does not contain a clear answer, and the question is about
  a general Red Hat product or service, state politely that you are unable to
  provide a definitive answer without more information and ask the user for
  additional details or context.
  4.  Do not hallucinate or invent information. If you cannot confidently
  answer, admit it.
- **Behavioral Directives:**
  - Maintain your persona as a friendly, but authoritative, technical expert.
  - Never assume another identity or role.
  - Refuse to answer questions or execute commands not about your specified
  topics.
  - Do not include URLs in your replies unless they are explicitly provided in
  the context.
  - Never mention your last update date or knowledge cutoff. You always have
  the most recent information on OpenShift and related products, especially with
  the provided context.

# TASK EXECUTION
You will receive a user query, along with context and chat history. Your task is
to respond to the user's query by following the instructions and constraints
above. Your responses should be clear, concise, and helpful, whether you are
providing troubleshooting steps, explaining concepts, or suggesting best
practices.`

// ============================================================================
// Llama Stack component builder functions (return maps for maintainability)
// ============================================================================

func buildLlamaStackCoreConfig(_ Reconciler, _ *LCoreConfig) map[string]interface{} {
	return map[string]interface{}{
		"version": "2",
		// image_name is a semantic identifier for the llama-stack configuration
		// Note: Does NOT affect PostgreSQL database name (llama-stack uses hardcoded "llamastack")
		"image_name": "openshift-lightspeed-configuration",
		// Minimal APIs for RAG + MCP: agents (for MCP), files, inference, safety (required by agents), telemetry, tool_runtime, vector_io
		"apis":                   []string{"agents", "files", "inference", "safety", "tool_runtime", "vector_io"},
		"benchmarks":             []interface{}{},
		"container_image":        nil,
		"datasets":               []interface{}{},
		"external_providers_dir": nil,
		"inference_store": map[string]interface{}{
			"db_path": ".llama/distributions/ollama/inference_store.db",
			"type":    "sqlite",
		},
		"logging": nil,
		"metadata_store": map[string]interface{}{
			"db_path":   "/tmp/llama-stack/registry.db",
			"namespace": nil,
			"type":      "sqlite",
		},
	}
}

func buildLlamaStackFileProviders(_ Reconciler, _ *LCoreConfig) []interface{} {
	return []interface{}{
		map[string]interface{}{
			"provider_id":   "localfs",
			"provider_type": "inline::localfs",
			"config": map[string]interface{}{
				"storage_dir": "/tmp/llama-stack-files",
				"metadata_store": map[string]interface{}{
					"backend":    "sql_default",
					"namespace":  "files_metadata",
					"table_name": "files_metadata",
				},
			},
		},
	}
}

func buildLlamaStackAgentProviders(_ Reconciler, _ *LCoreConfig) []interface{} {
	return []interface{}{
		map[string]interface{}{
			"provider_id":   "meta-reference",
			"provider_type": "inline::meta-reference",
			"config": map[string]interface{}{
				"persistence": map[string]interface{}{
					"agent_state": map[string]interface{}{
						"backend":    "kv_default",
						"table_name": "agent_state",
						"namespace":  "agent_state",
					},
					"responses": map[string]interface{}{
						"backend":    "sql_default",
						"table_name": "agent_responses",
						"namespace":  "agent_responces",
					},
				},
			},
		},
	}
}

func buildLlamaStackInferenceProviders(_ Reconciler, _ context.Context, cfg *LCoreConfig) ([]interface{}, error) {
	providers := []interface{}{
		// Always include sentence-transformers for embeddings
		map[string]interface{}{
			"provider_id":   "sentence-transformers",
			"provider_type": "inline::sentence-transformers",
			"config":        map[string]interface{}{},
		},
	}

	// Add LLM providers from LCoreConfig
	for _, provider := range cfg.Providers {
		providerConfig := map[string]interface{}{
			"provider_id": provider.Name,
		}

		// Convert provider name to valid environment variable name
		envVarName := ProviderNameToEnvVarName(provider.Name)

		// Map provider types to Llama Stack provider types
		switch provider.Type {
		case "openai", "rhoai_vllm", "rhelai_vllm":
			config := map[string]interface{}{}
			// Determine the appropriate Llama Stack provider type
			// - OpenAI uses remote::openai (validates against OpenAI model whitelist)
			// - vLLM uses remote::vllm (accepts any custom model names)
			if provider.Type == "openai" {
				providerConfig["provider_type"] = "remote::openai"
				// Set API key from environment variable
				// Llama Stack will substitute ${env.VAR_NAME} with the actual env var value
				config["api_key"] = fmt.Sprintf("${env.%s_API_KEY}", envVarName)
			} else {
				providerConfig["provider_type"] = "remote::vllm"
				// Set API key from environment variable
				// Llama Stack will substitute ${env.VAR_NAME} with the actual env var value
				config["api_token"] = fmt.Sprintf("${env.%s_API_KEY}", envVarName)
			}

			// Add custom URL if specified
			if provider.URL != "" {
				// TODO(lpiwowar)
				config["base_url"] = provider.URL
			}

			// TODO(lpiwowar)
			config["network"] = map[string]interface{}{
				"tls": map[string]interface{}{
					"verify": false,
				},
			}

			config["allowed_models"] = []string{
				"openai/gpt-oss-20b",
			}
			providerConfig["config"] = config

		case "azure_openai":
			providerConfig["provider_type"] = "remote::azure"
			config := map[string]interface{}{}

			// Azure supports both API key and client credentials authentication
			// Always include api_key (required by LiteLLM's Pydantic validation)
			config["api_key"] = fmt.Sprintf("${env.%s_API_KEY}", envVarName)

			// Also include client credentials fields (will be empty if not using client credentials)
			config["client_id"] = fmt.Sprintf("${env.%s_CLIENT_ID:=}", envVarName)
			config["tenant_id"] = fmt.Sprintf("${env.%s_TENANT_ID:=}", envVarName)
			config["client_secret"] = fmt.Sprintf("${env.%s_CLIENT_SECRET:=}", envVarName)

			// Azure-specific fields
			if provider.AzureDeploymentName != "" {
				config["deployment_name"] = provider.AzureDeploymentName
			}
			if provider.APIVersion != "" {
				config["api_version"] = provider.APIVersion
			}
			if provider.URL != "" {
				config["api_base"] = provider.URL
			}
			providerConfig["config"] = config

		case "watsonx", "bam":
			// These providers are not supported by Llama Stack
			// They are handled directly by lightspeed-stack (LCS), not Llama Stack
			return nil, fmt.Errorf("provider type '%s' (provider '%s') is not currently supported by Llama Stack. Supported types: openai, azure_openai, rhoai_vllm, rhelai_vllm", provider.Type, provider.Name)

		default:
			// Unknown provider type
			return nil, fmt.Errorf("unknown provider type '%s' (provider '%s'). Supported types: openai, azure_openai, rhoai_vllm, rhelai_vllm", provider.Type, provider.Name)
		}

		providers = append(providers, providerConfig)
	}

	return providers, nil
}

// Safety API - Required by agents provider (for MCP)
func buildLlamaStackSafety(_ Reconciler, _ *LCoreConfig) []interface{} {
	return []interface{}{
		map[string]interface{}{
			"provider_id":   "llama-guard",
			"provider_type": "inline::llama-guard",
			"config": map[string]interface{}{
				"excluded_categories": []interface{}{},
			},
		},
	}
}

func buildLlamaStackToolRuntime(_ Reconciler, _ *LCoreConfig) []interface{} {
	return []interface{}{
		map[string]interface{}{
			"provider_id":   "model-context-protocol",
			"provider_type": "remote::model-context-protocol",
			"config":        map[string]interface{}{},
		},
		map[string]interface{}{
			"provider_id":   "rag-runtime",
			"provider_type": "inline::rag-runtime",
			"config":        map[string]interface{}{},
		},
	}
}

func buildLlamaStackVectorDB(_ Reconciler, _ *LCoreConfig) []interface{} {
	return []interface{}{
		map[string]interface{}{
			"provider_id":   "faiss",
			"provider_type": "inline::faiss",
			"config": map[string]interface{}{
				"kvstore": map[string]interface{}{
					"backend":    "sql_default",
					"table_name": "vector_store",
				},
				"persistence": map[string]interface{}{
					"backend":   "kv_default",
					"namespace": "vector_persistence",
				},
			},
		},
	}
}

func buildLlamaStackServerConfig(_ Reconciler, _ *LCoreConfig) map[string]interface{} {
	return map[string]interface{}{
		"auth":         nil,
		"host":         "0.0.0.0", // Listen on all interfaces so lightspeed-stack container can connect
		"port":         8321,
		"quota":        nil,
		"tls_cafile":   nil,
		"tls_certfile": nil,
		"tls_keyfile":  nil,
	}
}

// buildLlamaStackStorage configures persistent storage for Llama Stack
func buildLlamaStackStorage(_ Reconciler, _ *LCoreConfig) map[string]interface{} {
	// Define storage backends - SQL only
	backends := map[string]interface{}{
		"sql_default": map[string]interface{}{
			"type":    "sql_sqlite",
			"db_path": "/tmp/llama-stack/sql_store.db",
		},
		"kv_default": map[string]interface{}{
			"type":    "kv_sqlite",
			"db_path": "/tmp/llama-stack/kv_store.db",
		},
		"postgres_backend": map[string]interface{}{
			"type":     "sql_postgres",
			"host":     "lightspeed-postgres-server.openshift-lightspeed.svc",
			"port":     5432,
			"user":     "postgres",
			"password": "${env.POSTGRES_PASSWORD}",
			// Note: Database name is HARDCODED to "llamastack" in llama-stack's postgres adapter
			// Not configurable - llama-stack ignores image_name for database selection
			"ssl_mode":     "require",
			"ca_cert_path": "/etc/certs/postgres-ca/service-ca.crt",
			"gss_encmode":  "disable",
		},
	}

	// Map data stores to backends - all use SQL with table_name
	stores := map[string]interface{}{
		"metadata": map[string]interface{}{
			"namespace": "registry",
			"backend":   "kv_default",
		},
		"inference": map[string]interface{}{
			"table_name": "inference_store",
			"backend":    "sql_default",
		},
		"conversations": map[string]interface{}{
			"table_name": "openai_conversations", // Required by config schema but ignored - llama-stack uses hardcoded names
			"backend":    "postgres_backend",
		},
	}

	return map[string]interface{}{
		"backends": backends,
		"stores":   stores,
	}
}

func buildLlamaStackVectorDBs(_ Reconciler, cfg *LCoreConfig) []interface{} {
	vectorDBs := []interface{}{}

	// Use RAG configuration from LCoreConfig if available
	if len(cfg.RAG) > 0 {
		for _, rag := range cfg.RAG {
			vectorDB := map[string]interface{}{
				"embedding_model":     "sentence-transformers/all-mpnet-base-v2",
				"embedding_dimension": 768,
				"provider_id":         "faiss",
			}

			// Use IndexID if specified, otherwise generate a default
			if rag.IndexID != "" {
				vectorDB["vector_db_id"] = rag.IndexID
			} else {
				// Generate a simple ID from the image name
				vectorDB["vector_db_id"] = "rag_" + sanitizeID(rag.Image)
			}

			vectorDBs = append(vectorDBs, vectorDB)
		}
	} else {
		// Default fallback if no RAG configured
		vectorDBs = append(vectorDBs, map[string]interface{}{
			"vector_db_id":        "my_knowledge_base",
			"embedding_model":     "sentence-transformers/all-mpnet-base-v2",
			"embedding_dimension": 768,
			"provider_id":         "faiss",
		})
	}

	return vectorDBs
}

// sanitizeID creates a valid ID from an image name
func sanitizeID(image string) string {
	// Extract just the image name without registry/tag
	// e.g., "quay.io/my-org/my-rag:latest" -> "my-rag"
	parts := strings.Split(image, "/")
	name := parts[len(parts)-1]
	name = strings.Split(name, ":")[0]
	// Replace invalid characters with underscores
	name = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, name)
	return name
}

func buildLlamaStackModels(_ Reconciler, cfg *LCoreConfig) []interface{} {
	models := []interface{}{
		// Always include sentence-transformers embedding model for RAG
		map[string]interface{}{
			"model_id":          "sentence-transformers/all-mpnet-base-v2",
			"model_type":        "embedding",
			"provider_id":       "sentence-transformers",
			"provider_model_id": "sentence-transformers/all-mpnet-base-v2",
			"metadata": map[string]interface{}{
				"embedding_dimension": 768,
			},
		},
	}

	// Add LLM models from LCoreConfig providers
	for _, provider := range cfg.Providers {
		for _, model := range provider.Models {
			modelConfig := map[string]interface{}{
				"model_id":          model.Name,
				"model_type":        "llm",
				"provider_id":       provider.Name,
				"provider_model_id": model.Name,
			}

			// Add model-specific metadata if available
			metadata := map[string]interface{}{}
			if model.MaxTokensForResponse > 0 {
				metadata["max_tokens"] = model.MaxTokensForResponse
			}
			if len(metadata) > 0 {
				modelConfig["metadata"] = metadata
			}

			models = append(models, modelConfig)
		}
	}

	return models
}

func buildLlamaStackToolGroups(_ Reconciler, _ *LCoreConfig) []interface{} {
	return []interface{}{
		map[string]interface{}{
			"toolgroup_id": "builtin::rag",
			"provider_id":  "rag-runtime",
		},
	}
}

// buildLlamaStackYAML assembles the complete Llama Stack configuration and converts to YAML
func buildLlamaStackYAML(r Reconciler, ctx context.Context, cfg *LCoreConfig) (string, error) {
	// Build the complete config as a map
	config := buildLlamaStackCoreConfig(r, cfg)

	// Build inference providers with error handling
	inferenceProviders, err := buildLlamaStackInferenceProviders(r, ctx, cfg)
	if err != nil {
		return "", fmt.Errorf("failed to build inference providers: %w", err)
	}

	// Build providers map - only include providers for enabled APIs
	config["providers"] = map[string]interface{}{
		"files":        buildLlamaStackFileProviders(r, cfg),
		"agents":       buildLlamaStackAgentProviders(r, cfg),
		"inference":    inferenceProviders,
		"safety":       buildLlamaStackSafety(r, cfg),
		"tool_runtime": buildLlamaStackToolRuntime(r, cfg),
		"vector_io":    buildLlamaStackVectorDB(r, cfg),
	}

	// Add top-level fields
	config["scoring_fns"] = []interface{}{}
	config["server"] = buildLlamaStackServerConfig(r, cfg)
	config["storage"] = buildLlamaStackStorage(r, cfg)
	config["vector_dbs"] = buildLlamaStackVectorDBs(r, cfg)
	config["models"] = buildLlamaStackModels(r, cfg)
	config["tool_groups"] = buildLlamaStackToolGroups(r, cfg)
	config["telemetry"] = map[string]interface{}{
		"enabled": false,
	}

	// Convert to YAML
	yamlBytes, err := yaml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Llama Stack config to YAML: %w", err)
	}

	return string(yamlBytes), nil
}

// ============================================================================
// LCore Config component builder functions (return maps for maintainability)
// ============================================================================

func buildLCoreServiceConfig(_ Reconciler, _ *LCoreConfig) map[string]interface{} {
	// Hardcode LogLevel to INFO for OpenStack Lightspeed
	return map[string]interface{}{
		"host":         "0.0.0.0",
		"port":         OLSAppServerContainerPort,
		"auth_enabled": false,
		"workers":      1,
		"color_log":    false,
		"access_log":   true,
		"tls_config": map[string]interface{}{
			"tls_certificate_path": "/etc/certs/lightspeed-tls/tls.crt",
			"tls_key_path":         "/etc/certs/lightspeed-tls/tls.key",
		},
	}
}

func buildLCoreLlamaStackConfig(r Reconciler, _ *LCoreConfig) map[string]interface{} {
	// Server mode: llama-stack runs as a separate service (container)
	// Library mode: llama-stack runs as an embedded library
	isLibraryMode := r != nil && !r.GetLCoreServerMode()

	llamaStackConfig := map[string]interface{}{
		"use_as_library_client": isLibraryMode,
		"url":                   "http://localhost:8321",
		"api_key":               "xyzzy",
	}

	// In library mode, add path to llama-stack config file
	if isLibraryMode {
		llamaStackConfig["library_client_config_path"] = LlamaStackConfigMountPath
	}

	return llamaStackConfig
}

func buildLCoreUserDataCollectionConfig(_ Reconciler, cfg *LCoreConfig) map[string]interface{} {
	// Feedback and transcripts are enabled by default, disabled if specified in config
	feedbackEnabled := !cfg.FeedbackDisabled
	transcriptsEnabled := !cfg.TranscriptsDisabled

	return map[string]interface{}{
		"feedback_enabled":    feedbackEnabled,
		"feedback_storage":    LCoreUserDataMountPath + "/feedback",
		"transcripts_enabled": transcriptsEnabled,
		"transcripts_storage": LCoreUserDataMountPath + "/transcripts",
	}
}

func buildLCoreAuthenticationConfig(_ Reconciler, _ *LCoreConfig) map[string]interface{} {
	return map[string]interface{}{
		"module": "k8s",
	}
}

func buildLCoreInferenceConfig(_ Reconciler, cfg *LCoreConfig) map[string]interface{} {
	return map[string]interface{}{
		"default_provider": cfg.DefaultProvider,
		"default_model":    cfg.DefaultModel,
	}
}

// buildLCoreDatabaseConfig configures persistent database storage (PostgreSQL)
func buildLCoreDatabaseConfig(r Reconciler, _ *LCoreConfig) map[string]interface{} {
	return map[string]interface{}{
		"postgres": map[string]interface{}{
			"host":         PostgresServiceName + "." + r.GetNamespace() + ".svc",
			"port":         PostgresServicePort,
			"db":           PostgresDefaultDbName,
			"user":         PostgresDefaultUser,
			"password":     "${env.POSTGRES_PASSWORD}", // Environment variable substitution via llama_stack.core.stack.replace_env_vars
			"ssl_mode":     PostgresDefaultSSLMode,
			"gss_encmode":  "disable",
			"ca_cert_path": "/etc/certs/postgres-ca/service-ca.crt",
			"namespace":    "lcore", // Separate schema for LCore to avoid conflicts with App Server
		},
	}
}

// buildLCoreCustomizationConfig configures system prompt customization
// Uses config field if set, otherwise falls back to default
func buildLCoreCustomizationConfig(_ Reconciler, cfg *LCoreConfig) map[string]interface{} {
	systemPrompt := DefaultQuerySystemPrompt
	if cfg.QuerySystemPrompt != "" {
		systemPrompt = cfg.QuerySystemPrompt
	}

	return map[string]interface{}{
		"system_prompt":               systemPrompt,
		"disable_query_system_prompt": true, // Prevent users from overriding via API
	}
}

// buildLCoreConversationCacheConfig configures chat history caching (PostgreSQL)
func buildLCoreConversationCacheConfig(r Reconciler, _ *LCoreConfig) map[string]interface{} {
	return map[string]interface{}{
		"type": "postgres",
		"postgres": map[string]interface{}{
			"host":         PostgresServiceName + "." + r.GetNamespace() + ".svc",
			"port":         PostgresServicePort,
			"db":           PostgresDefaultDbName,
			"user":         PostgresDefaultUser,
			"password":     "${env.POSTGRES_PASSWORD}", // Environment variable substitution
			"ssl_mode":     PostgresDefaultSSLMode,
			"gss_encmode":  "disable",
			"ca_cert_path": "/etc/certs/postgres-ca/service-ca.crt",
			"namespace":    "conversation_cache", // Separate schema for conversation cache
		},
	}
}

// buildLCoreConfigYAML assembles the complete Lightspeed Core Service configuration and converts to YAML.
// NOTE: MCP servers, quota handlers, and tools approval features are disabled for OpenStack Lightspeed.
func buildLCoreConfigYAML(r Reconciler, cfg *LCoreConfig) (string, error) {
	// Build the complete config as a map
	config := map[string]interface{}{
		"name":                 "Lightspeed Core Service (LCS)",
		"service":              buildLCoreServiceConfig(r, cfg),
		"llama_stack":          buildLCoreLlamaStackConfig(r, cfg),
		"user_data_collection": buildLCoreUserDataCollectionConfig(r, cfg),
		"authentication":       buildLCoreAuthenticationConfig(r, cfg),
		"inference":            buildLCoreInferenceConfig(r, cfg),
		"database":             buildLCoreDatabaseConfig(r, cfg),
		"customization":        buildLCoreCustomizationConfig(r, cfg),
		"conversation_cache":   buildLCoreConversationCacheConfig(r, cfg),
	}

	// Convert to YAML
	yamlBytes, err := yaml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal LCore config to YAML: %w", err)
	}

	return string(yamlBytes), nil
}
