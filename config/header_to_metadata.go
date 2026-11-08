package config

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	headertometadata "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
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
