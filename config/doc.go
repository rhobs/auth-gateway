// Package config loads and validates auth-gateway YAML, then generates Envoy
// files or Kubernetes resources.
//
// Start with Load for YAML, or Config.Validate for a Config built in Go.
// Use Generate for file-based Envoy output, GenerateOTelCollectorConfig for
// the collector file, or GenerateKubernetes for Kubernetes resources.
// LoadAPIKeyCredentials and APIKeySecret build the external API-key Secret separately.
//
// Callers should treat error text as diagnostic only, without matching
// on it or relying on errors.Is or errors.As to classify failures.
//
// Types and their methods live together in domain-named files.
// Standalone Envoy builders live in concern-named files; http_filters.go defines their order.
package config
