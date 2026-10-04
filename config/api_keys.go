package config

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	matching "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	apikey "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/api_key_auth/v3"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	apiKeyFilterName        = "envoy.filters.http.api_key_auth"
	apiKeySecretFilename    = "api-keys.yaml"
	apiKeyClientHeader      = "x-auth-gateway-api-key-client"
	apiKeyMetadataNamespace = "auth_gateway.api_key"
	apiKeyMetadataKey       = "identity"
	apiKeyAuthenticatorKey  = "authenticator"
	apiKeyAttributesKey     = "attributes"
)

// APIKeyCredential binds an opaque key to verified string attributes.
type APIKeyCredential struct {
	Key        string            `yaml:"key"`
	Attributes map[string]string `yaml:"attributes,omitempty"`
}

// APIKeySecret builds the complete ECDS resource in one Kubernetes Secret.
// An empty credential list revokes all keys. The Secret is not part of GenerateKubernetes.
func APIKeySecret(namespace string, authenticator Authenticator, credentials []APIKeyCredential) (*corev1.Secret, error) {
	if len(validation.IsDNS1123Label(namespace)) != 0 {
		return nil, fmt.Errorf("namespace must be a Kubernetes DNS label")
	}
	if !apiNamePattern.MatchString(authenticator.Name) || authenticator.JWT != nil || authenticator.APIKey == nil {
		return nil, fmt.Errorf("authenticator must be a named API-key authenticator")
	}
	apiKey := authenticator.APIKey.withDefaults()
	if err := validateAPIKeyAuthenticator("authenticator.api_key", apiKey); err != nil {
		return nil, err
	}
	allowedAttributes := make(map[string]struct{}, len(apiKey.Attributes))
	for _, attribute := range apiKey.Attributes {
		allowedAttributes[attribute] = struct{}{}
	}
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
		attributes := make(map[string]*structpb.Value, len(credential.Attributes))
		for name, value := range credential.Attributes {
			if _, exists := allowedAttributes[name]; !exists {
				return nil, fmt.Errorf("credentials[%d].attributes contains undeclared attribute %q", index, name)
			}
			if !validCredentialText(value) {
				return nil, fmt.Errorf("credentials[%d].attributes.%s must be a nonempty HTTP header value without controls", index, name)
			}
			attributes[name] = structpb.NewStringValue(value)
		}
		identity := structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
			apiKeyAuthenticatorKey: structpb.NewStringValue(authenticator.Name),
			apiKeyAttributesKey:    structpb.NewStructValue(&structpb.Struct{Fields: attributes}),
		}})
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(identity)
		if err != nil {
			return nil, fmt.Errorf("encode credentials[%d] identity: %w", index, err)
		}
		entries = append(entries, &apikey.Credential{Key: credential.Key, Client: base64.StdEncoding.EncodeToString(encoded)})
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
		return nil, fmt.Errorf("encode API-key Secret data: %w", err)
	}
	return &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: apiKey.Secret, Namespace: namespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{apiKeySecretFilename: data},
	}, nil
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
