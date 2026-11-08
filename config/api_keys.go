package config

import (
	"fmt"
	"io"
	"maps"
	"strings"

	yaml "go.yaml.in/yaml/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	apiKeySecretFilename           = "api-keys.yaml"
	apiKeyClientHeader             = "x-auth-gateway-api-key-client"
	apiKeyMetadataNamespace        = "auth_gateway.api_key"
	apiKeyMetadataKey              = "identity"
	apiKeyAttributeKey             = "attribute."
	apiKeyVerifiedIdentity         = "verified"
	requestHeaderMetadataNamespace = "auth_gateway.request_headers"
	defaultAPIKeyHeader            = "X-API-Key"
)

// APIKeyAuthenticator reads keys from an ECDS file.
type APIKeyAuthenticator struct {
	Secret string `yaml:"secret,omitempty"`
	Header string `yaml:"header,omitempty"`
}

// APIKeyCredential binds an opaque key to verified string attributes.
type APIKeyCredential struct {
	Key        string            `yaml:"key"`
	Attributes map[string]string `yaml:"attributes,omitempty"`
}

// LoadAPIKeyCredentials reads one credentials YAML document.
func LoadAPIKeyCredentials(r io.Reader) ([]APIKeyCredential, error) {
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	var input struct {
		Credentials *[]APIKeyCredential `yaml:"credentials"`
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

// APIKeySecret builds the complete ECDS resource in one Kubernetes Secret.
// An empty credential list revokes all keys. The Secret is not part of GenerateKubernetes.
func APIKeySecret(namespace string, authenticator Authenticator, credentials []APIKeyCredential) (*corev1.Secret, error) {
	if len(validation.IsDNS1123Label(namespace)) != 0 {
		return nil, fmt.Errorf("namespace must be a Kubernetes DNS label")
	}
	data, err := generateAPIKeyECDS(authenticator, credentials, true)
	if err != nil {
		return nil, err
	}
	return &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: authenticator.APIKey.Secret, Namespace: namespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{apiKeySecretFilename: data},
	}, nil
}

// GenerateAPIKeyECDS builds the file Envoy watches for API-key updates.
// An empty credential list revokes all keys.
func GenerateAPIKeyECDS(authenticator Authenticator, credentials []APIKeyCredential) ([]byte, error) {
	return generateAPIKeyECDS(authenticator, credentials, false)
}

func apiKeyAttributeMetadataKey(attribute string) string {
	return apiKeyAttributeKey + attribute
}

func validCredentialText(value string) bool {
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

func validateAPIKeyAuthenticator(name string, apiKey APIKeyAuthenticator, requireSecret bool) error {
	if (requireSecret || apiKey.Secret != "") && len(validation.IsDNS1123Subdomain(apiKey.Secret)) != 0 {
		return fmt.Errorf("%s.secret must be a Kubernetes Secret name", name)
	}
	if !validHeaderFieldName(apiKey.Header) || strings.Contains(apiKey.Header, "_") || forbiddenIdentityHeader(strings.ToLower(apiKey.Header)) {
		return fmt.Errorf("%s.header must be a safe HTTP credential header name", name)
	}
	return nil
}

func (a APIKeyAuthenticator) withDefaults() APIKeyAuthenticator {
	if a.Header == "" {
		a.Header = defaultAPIKeyHeader
	}
	return a
}

func (c APIKeyCredential) clone() APIKeyCredential {
	c.Attributes = maps.Clone(c.Attributes)
	return c
}
