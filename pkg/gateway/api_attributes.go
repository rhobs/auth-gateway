package gateway

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	setfilterstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

const apiFixedAttributeFilterName = "auth_gateway.api_attributes"

func validateAPIFixedAttributes(field string, attributes []gatewayapi.AttributeSource) error {
	seen := make(map[string]bool, len(attributes))
	for i, source := range attributes {
		name := fmt.Sprintf(attributeIndexFieldFormat, field, i)
		if !attributeNamePattern.MatchString(source.Name) {
			return fmt.Errorf("%s.name must be a valid attribute name", name)
		}
		if seen[source.Name] {
			return fmt.Errorf("%s.name duplicates attribute %q", name, source.Name)
		}
		seen[source.Name] = true
		if source.FromSource != "fixed" {
			return fmt.Errorf("%s.from_source must be fixed", name)
		}
		if source.Value.IsPath || !validAPIFixedAttributeValue(source.Value.Text) {
			return fmt.Errorf("%s.value must be a nonempty string without controls or surrounding whitespace", name)
		}
	}
	return nil
}

func validAPIFixedAttributeValue(value string) bool {
	if !utf8.ValidString(value) || !validCredentialText(value) {
		return false
	}
	for _, ch := range value {
		if unicode.IsControl(ch) {
			return false
		}
	}
	return true
}

func apiHasFixedAttribute(api gatewayapi.API, name string) bool {
	for _, source := range api.Attributes {
		if source.Name == name {
			return true
		}
	}
	return false
}

func hasAPIFixedAttributes(apis []gatewayapi.API) bool {
	for _, api := range apis {
		if len(api.Attributes) != 0 {
			return true
		}
	}
	return false
}

func validateAPIFixedAttributeCollisions(field string, api gatewayapi.API, access resolvedAccess, services map[string]gatewayapi.ExternalAuthorizationService) error {
	for _, authenticator := range access.authenticators {
		for _, source := range authenticator.Attributes {
			if apiHasFixedAttribute(api, source.Name) {
				return fmt.Errorf("%s authenticator %q attribute %q conflicts with a fixed attribute on API %q", field, authenticator.Name, source.Name, api.Name)
			}
		}
	}
	if access.Authorization.ExtAuthz != nil {
		service := services[access.Authorization.ExtAuthz.Service]
		for _, source := range service.Attributes {
			if apiHasFixedAttribute(api, source.Name) {
				return fmt.Errorf("%s external authorization attribute %q conflicts with a fixed attribute on API %q", field, source.Name, api.Name)
			}
		}
	}
	return nil
}

func apiFixedAttributeHTTPFilter() (*hcm.HttpFilter, error) {
	packed, err := packEnvoy(&setfilterstate.Config{})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: apiFixedAttributeFilterName, Disabled: true, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: packed}}, nil
}

func apiFixedAttributePerRouteConfig(attributes []gatewayapi.AttributeSource) (*anypb.Any, error) {
	config := &setfilterstate.Config{}
	for _, source := range slices.SortedFunc(slices.Values(attributes), func(a, b gatewayapi.AttributeSource) int {
		return strings.Compare(a.Name, b.Name)
	}) {
		format := fmt.Sprintf("%%METADATA(ROUTE:%s:%s)%%", apiFixedAttributeFilterName, source.Name)
		config.OnRequestHeaders = append(config.OnRequestHeaders, filterStateFormatValue(filterStateKey(source.Name), format))
	}
	packed, err := packEnvoy(config)
	if err != nil {
		return nil, err
	}
	return packEnvoy(&route.FilterConfig{Config: packed})
}

func addAPIFixedAttributeRouteConfigs(routes []*route.Route, apis []gatewayapi.API) error {
	routesByName := make(map[string]*route.Route, len(routes))
	for _, generated := range routes {
		routesByName[generated.Name] = generated
	}
	for apiIndex, api := range apis {
		if len(api.Attributes) == 0 {
			continue
		}
		perRoute, err := apiFixedAttributePerRouteConfig(api.Attributes)
		if err != nil {
			return fmt.Errorf("encode fixed attributes for API %q: %w", api.Name, err)
		}
		values := make(map[string]*structpb.Value, len(api.Attributes))
		for _, source := range api.Attributes {
			values[source.Name] = structpb.NewStringValue(source.Value.Text)
		}
		for routeIndex, apiRoute := range api.Routes {
			for methodIndex := range apiRoute.Methods {
				name := apiRouteName(apiIndex, api.Name, routeIndex, methodIndex)
				generated := routesByName[name]
				if generated == nil {
					return fmt.Errorf("generated route %q is missing", name)
				}
				if generated.Metadata == nil {
					generated.Metadata = &core.Metadata{}
				}
				if generated.Metadata.FilterMetadata == nil {
					generated.Metadata.FilterMetadata = make(map[string]*structpb.Struct)
				}
				generated.Metadata.FilterMetadata[apiFixedAttributeFilterName] = &structpb.Struct{Fields: values}
				if generated.TypedPerFilterConfig == nil {
					generated.TypedPerFilterConfig = make(map[string]*anypb.Any)
				}
				generated.TypedPerFilterConfig[apiFixedAttributeFilterName] = perRoute
			}
		}
	}
	return nil
}
