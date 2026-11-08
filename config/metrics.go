package config

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

const (
	defaultRequestMetricCounterName = "auth_gateway_http_requests_total"
	requestMetricStatusLabelName    = "http_status_code"
)

var prometheusNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// APIMetrics enables one request counter and optionally binds labels to working attributes.
type APIMetrics struct {
	Labels map[string]string `yaml:"labels,omitempty"`
}

func (m APIMetrics) clone() APIMetrics {
	m.Labels = maps.Clone(m.Labels)
	return m
}

func validateCustomMetricName(value *string) error {
	if value != nil && (!prometheusNamePattern.MatchString(*value) || strings.HasPrefix(*value, "__")) {
		return fmt.Errorf("observability.metrics.custom_metric_name must start with an ASCII letter or underscore, use only ASCII letters, numbers, and underscores, and not start with __")
	}
	return nil
}

func validateAPIMetrics(name string, value *APIMetrics) error {
	if value == nil {
		return nil
	}
	for _, label := range slices.Sorted(maps.Keys(value.Labels)) {
		if !prometheusNamePattern.MatchString(label) || strings.HasPrefix(label, "__") ||
			label == apiMetadataName || label == requestMetricStatusLabelName || label == "envoy_http_conn_manager_prefix" {
			return fmt.Errorf("%s.labels contains invalid or reserved Prometheus label name %q", name, label)
		}
		if !attributeNamePattern.MatchString(value.Labels[label]) {
			return fmt.Errorf("%s.labels.%s must reference a valid attribute name", name, label)
		}
	}
	return nil
}

func validateMetricAttributeReferences(apis []API, authenticators map[string]Authenticator) error {
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

func hasRequestMetricLabels(apis []API) bool {
	for _, api := range apis {
		if api.Metrics != nil && len(api.Metrics.Labels) > 0 {
			return true
		}
	}
	return false
}

func requestMetricLabelNames(apis []API) []string {
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
