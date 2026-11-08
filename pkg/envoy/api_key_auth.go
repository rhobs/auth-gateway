package envoy

import (
	"fmt"
	"slices"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	apikey "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/api_key_auth/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	yaml "go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	apiKeyFilterName         = "envoy.filters.http.api_key_auth"
	apiKeyClientNoAttributes = "api-key"
)

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
	authenticator, err = configuration.ResolveAPIKeyAuthenticator(authenticator, requireSecret)
	if err != nil {
		return nil, err
	}
	apiKey := *authenticator.APIKey
	attributeNames := configuration.CredentialAttributeNamesAuthenticator(authenticator)
	allowedAttributes := make(map[string]struct{}, len(attributeNames))
	for _, attribute := range attributeNames {
		allowedAttributes[attribute] = struct{}{}
	}
	seenKeys := make(map[string]struct{}, len(credentials))
	entries := make([]*apikey.Credential, 0, len(credentials))
	for index, credential := range credentials {
		if !configuration.ValidCredentialText(credential.Key) {
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
			if !configuration.ValidCredentialText(value) || strings.Contains(value, ";") {
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
		Forwarding:  &apikey.Forwarding{Header: configuration.ApiKeyClientHeader, HideCredentials: true},
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
	data, err := yaml.Marshal(map[string]any{configuration.EnvoyResourcesFieldName: []any{document}})
	if err != nil {
		return nil, fmt.Errorf("encode API-key ECDS data: %w", err)
	}
	return data, nil
}

func apiKeyFilter() *hcm.HttpFilter {
	return &hcm.HttpFilter{
		Name: apiKeyFilterName, Disabled: true,
		ConfigType: &hcm.HttpFilter_ConfigDiscovery{ConfigDiscovery: &core.ExtensionConfigSource{
			ConfigSource: fileConfigSource(configuration.APIKeyECDSPath),
			TypeUrls:     []string{extensionWithMatcherTypeName()},
		}},
	}
}

func addServerAPIKeyConfig(c configuration.ResolvedConfig, host *route.VirtualHost, index int, server configuration.ResolvedServer) error {
	if !server.HasAPIKey {
		return nil
	}
	perRoute, err := toAPIKeyPerRouteConfig(c, server)
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
