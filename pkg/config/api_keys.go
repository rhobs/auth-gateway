package config

import (
	"fmt"
	"io"
	"strings"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	yaml "go.yaml.in/yaml/v3"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	ApiKeySecretFilename           = "api-keys.yaml"
	ApiKeyClientHeader             = "x-auth-gateway-api-key-client"
	ApiKeyMetadataNamespace        = "auth_gateway.api_key"
	ApiKeyMetadataKey              = "identity"
	ApiKeyAttributeKey             = "attribute."
	ApiKeyVerifiedIdentity         = "verified"
	RequestHeaderMetadataNamespace = "auth_gateway.request_headers"
	DefaultAPIKeyHeader            = "X-API-Key"
)

// LoadAPIKeyCredentials reads one credentials YAML document.
func LoadAPIKeyCredentials(r io.Reader) ([]gatewayapi.APIKeyCredential, error) {
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	var input struct {
		Credentials *[]gatewayapi.APIKeyCredential `yaml:"credentials"`
	}
	if err := decoder.Decode(&input); err != nil {
		return nil, err
	}
	if input.Credentials == nil {
		return nil, fmt.Errorf("credentials document must set credentials (use [] to revoke all keys)")
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return nil, fmt.Errorf("credentials document must contain exactly one YAML document")
	} else if err != io.EOF {
		return nil, err
	}
	return *input.Credentials, nil
}

func ApiKeyAttributeMetadataKey(attribute string) string {
	return ApiKeyAttributeKey + attribute
}

func ValidCredentialText(value string) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	for _, ch := range value {
		if ch < 0x20 || ch == 0x7f {
			return false
		}
	}
	return true
}

func validateAPIKeyAuthenticator(name string, apiKey gatewayapi.APIKeyAuthenticator, requireSecret bool) error {
	if (requireSecret || apiKey.Secret != "") && len(validation.IsDNS1123Subdomain(apiKey.Secret)) != 0 {
		return fmt.Errorf("%s.secret must be a Kubernetes Secret name", name)
	}
	if !validHeaderFieldName(apiKey.Header) || strings.Contains(apiKey.Header, "_") || ForbiddenIdentityHeader(strings.ToLower(apiKey.Header)) {
		return fmt.Errorf("%s.header must be a safe HTTP credential header name", name)
	}
	return nil
}

func withDefaultsAPIKeyAuthenticator(a gatewayapi.APIKeyAuthenticator) gatewayapi.APIKeyAuthenticator {
	if a.Header == "" {
		a.Header = DefaultAPIKeyHeader
	}
	return a
}

func ResolveAPIKeyAuthenticator(authenticator gatewayapi.Authenticator, requireSecret bool) (gatewayapi.Authenticator, error) {
	if !ApiNamePattern.MatchString(authenticator.Name) || authenticator.JWT != nil || authenticator.MTLS != nil || authenticator.APIKey == nil {
		return gatewayapi.Authenticator{}, fmt.Errorf("authenticator must be a named API-key authenticator")
	}
	apiKey := withDefaultsAPIKeyAuthenticator(*authenticator.APIKey)
	if err := validateAPIKeyAuthenticator("authenticator.api_key", apiKey, requireSecret); err != nil {
		return gatewayapi.Authenticator{}, err
	}
	authenticator.APIKey = &apiKey
	if err := validateAuthenticatorAttributes("authenticator", authenticator, apiKey.Header); err != nil {
		return gatewayapi.Authenticator{}, err
	}
	return authenticator, nil
}
