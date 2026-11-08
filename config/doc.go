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
// Configuration types, defaults, and validation live in domain-named files.
// Envoy extensions live in files named for each extension; http_filters.go defines their order.
package config
