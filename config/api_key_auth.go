package config

import (
	"fmt"
	"slices"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	apikey "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/api_key_auth/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	yaml "go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	apiKeyFilterName         = "envoy.filters.http.api_key_auth"
	apiKeyClientNoAttributes = "api-key"
)

func generateAPIKeyECDS(authenticator Authenticator, credentials []APIKeyCredential, requireSecret bool) ([]byte, error) {
	if !apiNamePattern.MatchString(authenticator.Name) || authenticator.JWT != nil || authenticator.MTLS != nil || authenticator.APIKey == nil {
		return nil, fmt.Errorf("authenticator must be a named API-key authenticator")
	}
	apiKey := authenticator.APIKey.withDefaults()
	if err := validateAPIKeyAuthenticator("authenticator.api_key", apiKey, requireSecret); err != nil {
		return nil, err
	}
	authenticator.APIKey = &apiKey
	if err := validateAuthenticatorAttributes("authenticator", authenticator, apiKey.Header); err != nil {
		return nil, err
	}
	attributeNames := authenticator.credentialAttributeNames()
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

func apiKeyFilter() *hcm.HttpFilter {
	return &hcm.HttpFilter{
		Name: apiKeyFilterName, Disabled: true,
		ConfigType: &hcm.HttpFilter_ConfigDiscovery{ConfigDiscovery: &core.ExtensionConfigSource{
			ConfigSource: fileConfigSource(APIKeyECDSPath),
			TypeUrls:     []string{extensionWithMatcherTypeName()},
		}},
	}
}

func addServerAPIKeyConfig(c effectiveConfig, host *route.VirtualHost, index int, server resolvedServer) error {
	if !server.hasAPIKey {
		return nil
	}
	perRoute, err := toAPIKeyPerRouteConfig(c, server)
	if err != nil {
		return fmt.Errorf("servers[%d] API-key matcher: %w", index, err)
	}
	host.TypedPerFilterConfig[apiKeyFilterName] = perRoute
	return nil
}
