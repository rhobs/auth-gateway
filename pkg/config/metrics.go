package config

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

const (
	DefaultRequestMetricCounterName = "auth_gateway_http_requests_total"
	RequestMetricStatusLabelName    = "http_status_code"
)

var PrometheusNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func cloneAPIMetrics(m gatewayapi.APIMetrics) gatewayapi.APIMetrics {
	m.Labels = maps.Clone(m.Labels)
	return m
}

func validateCustomMetricName(value *string) error {
	if value != nil && (!PrometheusNamePattern.MatchString(*value) || strings.HasPrefix(*value, "__")) {
		return fmt.Errorf("observability.metrics.custom_metric_name must start with an ASCII letter or underscore, use only ASCII letters, numbers, and underscores, and not start with __")
	}
	return nil
}

func validateAPIMetrics(name string, value *gatewayapi.APIMetrics) error {
	if value == nil {
		return nil
	}
	for _, label := range slices.Sorted(maps.Keys(value.Labels)) {
		if !PrometheusNamePattern.MatchString(label) || strings.HasPrefix(label, "__") ||
			label == ApiMetadataName || label == RequestMetricStatusLabelName || label == "envoy_http_conn_manager_prefix" {
			return fmt.Errorf("%s.labels contains invalid or reserved Prometheus label name %q", name, label)
		}
		if !AttributeNamePattern.MatchString(value.Labels[label]) {
			return fmt.Errorf("%s.labels.%s must reference a valid attribute name", name, label)
		}
	}
	return nil
}

func validateMetricAttributeReferences(apis []gatewayapi.API, authenticators map[string]gatewayapi.Authenticator) error {
	known := make(map[string]struct{})
	for _, authenticator := range authenticators {
		for attribute := range authenticator.Attributes {
			known[attribute] = struct{}{}
		}
	}
	for i, api := range apis {
		if api.Metrics == nil {
			continue
		}
		for _, label := range slices.Sorted(maps.Keys(api.Metrics.Labels)) {
			attribute := api.Metrics.Labels[label]
			if _, exists := known[attribute]; !exists {
				return fmt.Errorf("apis[%d].metrics.labels.%s references unknown authenticator attribute %q", i, label, attribute)
			}
		}
	}
	return nil
}

func HasRequestMetricLabels(apis []gatewayapi.API) bool {
	for _, api := range apis {
		if api.Metrics != nil && len(api.Metrics.Labels) > 0 {
			return true
		}
	}
	return false
}

func RequestMetricLabelNames(apis []gatewayapi.API) []string {
	labels := make(map[string]struct{})
	for _, api := range apis {
		if api.Metrics == nil {
			continue
		}
		for label := range api.Metrics.Labels {
			labels[label] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(labels))
}
