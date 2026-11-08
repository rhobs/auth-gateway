package config

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	headertometadata "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
)

const (
	// Envoy's header_to_metadata filter rejects values of 8 KiB or more.
	apiKeyMaxAttributeBytes    = 8*1024 - 1
	headerToMetadataFilterName = "envoy.filters.http.header_to_metadata"
)

func requestHeaderSources(c effectiveConfig, serverIndexes []int) []string {
	headers := make(map[string]struct{})
	for _, index := range serverIndexes {
		for _, authenticator := range c.servers[index].authenticators {
			for _, source := range authenticator.Attributes {
				if source.Header != nil {
					headers[strings.ToLower(*source.Header)] = struct{}{}
				}
			}
		}
	}
	return slices.Sorted(maps.Keys(headers))
}

func (authenticator Authenticator) toRequestMetadataFilter(headers []string, includeMTLS bool) (*hcm.HttpFilter, error) {
	var rules []*headertometadata.Config_Rule
	if authenticator.APIKey != nil {
		attributeNames := authenticator.credentialAttributeNames()
		rules = append(rules, &headertometadata.Config_Rule{
			Header: apiKeyClientHeader, Remove: len(attributeNames) == 0,
			OnHeaderPresent: &headertometadata.Config_KeyValuePair{
				MetadataNamespace: apiKeyMetadataNamespace, Key: apiKeyMetadataKey,
				Value: apiKeyVerifiedIdentity,
			},
		})
		for index, attribute := range attributeNames {
			rules = append(rules, &headertometadata.Config_Rule{
				Header: apiKeyClientHeader, Remove: index == len(attributeNames)-1,
				OnHeaderPresent: &headertometadata.Config_KeyValuePair{
					MetadataNamespace: apiKeyMetadataNamespace,
					Key:               apiKeyAttributeMetadataKey(attribute),
					RegexValueRewrite: &matcher.RegexMatchAndSubstitute{
						Pattern:      &matcher.RegexMatcher{Regex: apiKeyAttributePattern(attribute)},
						Substitution: `\1`,
					},
				},
			})
		}
	}
	if includeMTLS {
		rules = append(rules, mtlsPeerMetadataRules()...)
	}
	for _, header := range headers {
		rules = append(rules, &headertometadata.Config_Rule{
			Header: header,
			OnHeaderPresent: &headertometadata.Config_KeyValuePair{
				MetadataNamespace: requestHeaderMetadataNamespace,
				Key:               header,
			},
		})
	}
	config, err := packEnvoy(&headertometadata.Config{RequestRules: rules})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: headerToMetadataFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: config}}, nil
}

func apiKeyAttributePattern(attribute string) string {
	// The fallback leaves an absent field's capture empty.
	return `^(?:(?:[^;]*;)*` + regexp.QuoteMeta(attribute) + `=([^;]*)(?:;[^;]*)*|.*)$`
}

func mtlsPeerMetadataRules() []*headertometadata.Config_Rule {
	values := []struct{ header, key string }{
		{mtlsFingerprintHeaderName, mtlsFingerprintMetadataKey},
		{mtlsURIHeaderName, mtlsURIMetadataKey},
		{mtlsDNSHeaderName, mtlsDNSMetadataKey},
	}
	rules := make([]*headertometadata.Config_Rule, 0, len(values))
	for _, value := range values {
		rules = append(rules, &headertometadata.Config_Rule{
			Header: value.header,
			OnHeaderPresent: &headertometadata.Config_KeyValuePair{
				MetadataNamespace: mtlsMetadataNamespace, Key: value.key,
			},
		})
	}
	return rules
}
