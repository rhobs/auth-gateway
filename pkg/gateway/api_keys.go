package gateway

import (
	"fmt"
	"io"
	"slices"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	apikey "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/api_key_auth/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	yaml "go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
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
	apiKeyFilterName               = "envoy.filters.http.api_key_auth"
	apiKeyClientNoAttributes       = "api-key"
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

func validateAPIKeyAuthenticator(name string, apiKey gatewayapi.APIKeyAuthenticator, requireSecret bool) error {
	if (requireSecret || apiKey.Secret != "") && len(validation.IsDNS1123Subdomain(apiKey.Secret)) != 0 {
		return fmt.Errorf("%s.secret must be a Kubernetes Secret name", name)
	}
	if !validHeaderFieldName(apiKey.Header) || strings.Contains(apiKey.Header, "_") || forbiddenIdentityHeader(strings.ToLower(apiKey.Header)) {
		return fmt.Errorf("%s.header must be a safe HTTP credential header name", name)
	}
	return nil
}

func withDefaultsAPIKeyAuthenticator(a gatewayapi.APIKeyAuthenticator) gatewayapi.APIKeyAuthenticator {
	if a.Header == "" {
		a.Header = defaultAPIKeyHeader
	}
	return a
}

func resolveAPIKeyAuthenticator(authenticator gatewayapi.Authenticator, requireSecret bool) (gatewayapi.Authenticator, error) {
	if !apiNamePattern.MatchString(authenticator.Name) || authenticator.JWT != nil || authenticator.MTLS != nil || authenticator.APIKey == nil {
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

func validateAPIKeyHeaderUse(c gatewayapi.Config, apiKeyHeader string) error {
	for i, api := range c.APIs {
		for j, route := range api.Routes {
			if route.Processing == nil {
				continue
			}
			for k, header := range route.Processing.RequestHeaders {
				if strings.EqualFold(header.Name, apiKeyHeader) {
					return fmt.Errorf("apis[%d].routes[%d].processing.request_headers[%d].name is reserved for API-key credentials", i, j, k)
				}
			}
		}
	}
	return nil
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

func generateAPIKeyECDS(authenticator gatewayapi.Authenticator, credentials []gatewayapi.APIKeyCredential, requireSecret bool) ([]byte, error) {
	var err error
	authenticator, err = resolveAPIKeyAuthenticator(authenticator, requireSecret)
	if err != nil {
		return nil, err
	}
	apiKey := *authenticator.APIKey
	attributeNames := credentialAttributeNamesAuthenticator(authenticator)
	allowedAttributes := make(map[string]struct{}, len(attributeNames))
	for _, attribute := range attributeNames {
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
		for name, value := range credential.Attributes {
			if _, exists := allowedAttributes[name]; !exists {
				return nil, fmt.Errorf("credentials[%d].attributes contains undeclared attribute %q", index, name)
			}
			if !validCredentialText(value) || strings.Contains(value, ";") {
				return nil, fmt.Errorf("credentials[%d].attributes.%s must be a nonempty HTTP header value without controls or semicolons", index, name)
			}
			if len(value) > apiKeyMaxAttributeBytes {
				return nil, fmt.Errorf("credentials[%d].attributes.%s must be at most %d bytes for Envoy metadata extraction", index, name, apiKeyMaxAttributeBytes)
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
	wrapped, err := extensionWithMatcherConfig(&core.TypedExtensionConfig{Name: apiKeyFilterName, TypedConfig: native})
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

func apiKeyFilter() *hcm.HttpFilter {
	return &hcm.HttpFilter{
		Name: apiKeyFilterName, Disabled: true,
		ConfigType: &hcm.HttpFilter_ConfigDiscovery{ConfigDiscovery: &core.ExtensionConfigSource{
			ConfigSource: fileConfigSource(APIKeyECDSPath),
			TypeUrls:     []string{extensionWithMatcherTypeName()},
		}},
	}
}

func addServerAPIKeyConfig(c resolvedConfig, host *route.VirtualHost, index int, server resolvedServer) error {
	if !server.hasAPIKey {
		return nil
	}
	perRoute, err := apiKeyPerRouteConfig(c, server)
	if err != nil {
		return fmt.Errorf("servers[%d] API-key matcher: %w", index, err)
	}
	host.TypedPerFilterConfig[apiKeyFilterName] = perRoute
	return nil
}

// GenerateAPIKeyECDS builds the file Envoy watches for API-key updates.
// An empty credential list revokes all keys.
func GenerateAPIKeyECDS(authenticator gatewayapi.Authenticator, credentials []gatewayapi.APIKeyCredential) ([]byte, error) {
	return generateAPIKeyECDS(authenticator, credentials, false)
}

// APIKeySecret builds the complete ECDS resource in one Kubernetes Secret.
// An empty credential list revokes all keys. The Secret is not part of GenerateKubernetes.
func APIKeySecret(namespace string, authenticator gatewayapi.Authenticator, credentials []gatewayapi.APIKeyCredential) (*corev1.Secret, error) {
	if len(validation.IsDNS1123Label(namespace)) != 0 {
		return nil, fmt.Errorf("namespace must be a Kubernetes DNS label")
	}
	authenticator, err := resolveAPIKeyAuthenticator(authenticator, true)
	if err != nil {
		return nil, err
	}
	data, err := GenerateAPIKeyECDS(authenticator, credentials)
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
