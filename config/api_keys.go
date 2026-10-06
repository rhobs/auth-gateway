package config

import (
	"fmt"
	"io"
	"slices"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	matching "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	apikey "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/api_key_auth/v3"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	apiKeyFilterName         = "envoy.filters.http.api_key_auth"
	apiKeySecretFilename     = "api-keys.yaml"
	apiKeyClientHeader       = "x-auth-gateway-api-key-client"
	apiKeyMetadataNamespace  = "auth_gateway.api_key"
	apiKeyMetadataKey        = "identity"
	apiKeyAttributeKey       = "attribute."
	apiKeyClientNoAttributes = "api-key"
)

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

func generateAPIKeyECDS(authenticator Authenticator, credentials []APIKeyCredential, requireSecret bool) ([]byte, error) {
	if !apiNamePattern.MatchString(authenticator.Name) || authenticator.JWT != nil || authenticator.APIKey == nil {
		return nil, fmt.Errorf("authenticator must be a named API-key authenticator")
	}
	apiKey := authenticator.APIKey.withDefaults()
	if err := validateAPIKeyAuthenticator("authenticator.api_key", apiKey, requireSecret); err != nil {
		return nil, err
	}
	allowedAttributes := make(map[string]struct{}, len(apiKey.Attributes))
	for _, attribute := range apiKey.Attributes {
		allowedAttributes[attribute] = struct{}{}
	}
	attributeNames := slices.Clone(apiKey.Attributes)
	slices.Sort(attributeNames)
	seenKeys := make(map[string]struct{}, len(credentials))
	entries := make([]*apikey.Credential, 0, len(credentials))
	for index, credential := range credentials {
		if !validCredentialText(credential.Key) {
			return nil, fmt.Errorf("credentials[%d].key must be a nonempty HTTP header value without controls", index)
		}
		if _, exists := seenKeys[credential.Key]; exists {
			return nil, fmt.Errorf("credentials[%d].key is duplicated", index)
		}
		seenKeys[credential.Key] = struct{}{}
		for name, value := range credential.Attributes {
			if _, exists := allowedAttributes[name]; !exists {
				return nil, fmt.Errorf("credentials[%d].attributes contains undeclared attribute %q", index, name)
			}
			if !validCredentialText(value) || strings.Contains(value, ";") {
				return nil, fmt.Errorf("credentials[%d].attributes.%s must be a nonempty HTTP header value without controls or semicolons", index, name)
			}
		}
		entries = append(entries, &apikey.Credential{Key: credential.Key, Client: apiKeyClientValue(attributeNames, credential.Attributes)})
	}
	slices.SortFunc(entries, func(a, b *apikey.Credential) int { return strings.Compare(a.Key, b.Key) })
	native, err := packEnvoy(&apikey.ApiKeyAuth{
		Credentials: entries,
		KeySources:  []*apikey.KeySource{{Header: strings.ToLower(apiKey.Header)}},
		Forwarding:  &apikey.Forwarding{Header: apiKeyClientHeader, HideCredentials: true},
	})
	if err != nil {
		return nil, fmt.Errorf("encode API-key filter: %w", err)
	}
	wrapped, err := packEnvoy(&matching.ExtensionWithMatcher{ExtensionConfig: &core.TypedExtensionConfig{Name: apiKeyFilterName, TypedConfig: native}})
	if err != nil {
		return nil, fmt.Errorf("encode API-key matcher: %w", err)
	}
	resource, err := packEnvoy(&core.TypedExtensionConfig{Name: apiKeyFilterName, TypedConfig: wrapped})
	if err != nil {
		return nil, fmt.Errorf("encode API-key ECDS resource: %w", err)
	}
	jsonData, err := (protojson.MarshalOptions{UseProtoNames: true, EmitDefaultValues: true}).Marshal(resource)
	if err != nil {
		return nil, fmt.Errorf("encode API-key ECDS response: %w", err)
	}
	var document any
	if err := yaml.Unmarshal(jsonData, &document); err != nil {
		return nil, fmt.Errorf("convert API-key ECDS response: %w", err)
	}
	data, err := yaml.Marshal(map[string]any{envoyResourcesFieldName: []any{document}})
	if err != nil {
		return nil, fmt.Errorf("encode API-key ECDS data: %w", err)
	}
	return data, nil
}

func apiKeyClientValue(attributeNames []string, values map[string]string) string {
	if len(attributeNames) == 0 {
		return apiKeyClientNoAttributes
	}
	var client strings.Builder
	for index, name := range attributeNames {
		if index > 0 {
			client.WriteByte(';')
		}
		client.WriteString(name)
		client.WriteByte('=')
		client.WriteString(values[name])
	}
	return client.String()
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
