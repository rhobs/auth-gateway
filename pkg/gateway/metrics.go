package gateway

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	metrics "github.com/envoyproxy/go-control-plane/envoy/config/metrics/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	lua "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	defaultRequestMetricCounterName = "auth_gateway_http_requests_total"
	requestMetricStatusLabelName    = "http_status_code"
	defaultOTelMetricsPort          = 8889
	requestMetricsFilterName        = "envoy.filters.http.lua"
	requestMetricsLuaBody           = `local function safe_label(value)
  if type(value) ~= "string" or #value == 0 or #value > 128 then
    return "__unattributed__"
  end
  for i = 1, #value do
    local byte = string.byte(value, i)
    if byte < 32 or byte > 126 or byte == 124 then
      return "__unattributed__"
    end
  end
  return value
end

function envoy_on_response(response_handle)
  local metadata = response_handle:metadata()
  if metadata == nil then
    return
  end
  local api = metadata:get("api")
  if type(api) ~= "string" or api == "" then
    return
  end
  local status = response_handle:headers():get(":status")
  if type(status) ~= "string" or not string.match(status, "^%d%d%d$") then
    return
  end

  local bindings = metadata:get("labels") or {}
  local filter_state = response_handle:streamInfo():filterState()
  local name = counter_name .. "|api=" .. api .. "|http_status_code=" .. status
  for _, label in ipairs(labels) do
    local attribute = bindings[label]
    local value = nil
    if type(attribute) == "string" then
      value = filter_state:get("auth_gateway.attributes." .. attribute)
    end
    name = name .. "|" .. label .. "=" .. safe_label(value)
  end
  response_handle:stats():counter(name):inc()
end
`
)

var (
	prometheusNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

func hasRequestMetrics(c gatewayapi.Config) bool {
	for _, api := range c.APIs {
		if api.Metrics != nil {
			return true
		}
	}
	return false
}

func requestMetricName(c gatewayapi.Config) string {
	if c.Observability.Metrics.CustomMetricName != nil {
		return *c.Observability.Metrics.CustomMetricName
	}
	return defaultRequestMetricCounterName
}

func cloneAPIMetrics(m gatewayapi.APIMetrics) gatewayapi.APIMetrics {
	m.Labels = maps.Clone(m.Labels)
	return m
}

func validateCustomMetricName(value *string) error {
	if value != nil && (!prometheusNamePattern.MatchString(*value) || strings.HasPrefix(*value, "__")) {
		return fmt.Errorf("observability.metrics.custom_metric_name must start with an ASCII letter or underscore, use only ASCII letters, numbers, and underscores, and not start with __")
	}
	return nil
}

func validateAPIMetrics(name string, value *gatewayapi.APIMetrics) error {
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

func validateMetricAttributeReferences(apis []gatewayapi.API, authenticators map[string]gatewayapi.Authenticator, servers []gatewayapi.Server, services map[string]gatewayapi.ExternalAuthorizationService) error {
	known := make(map[string]struct{})
	for _, authenticator := range authenticators {
		for _, attribute := range authenticator.Attributes {
			known[attribute.Name] = struct{}{}
		}
	}
	for _, server := range servers {
		for _, binding := range server.APIs {
			for _, access := range binding.Access {
				if access.Authorization.ExtAuthz != nil {
					service := services[access.Authorization.ExtAuthz.Service]
					for _, attribute := range service.Attributes {
						known[attribute.Name] = struct{}{}
					}
				}
			}
		}
	}
	for i, api := range apis {
		if api.Metrics == nil {
			continue
		}
		for _, label := range slices.Sorted(maps.Keys(api.Metrics.Labels)) {
			attribute := api.Metrics.Labels[label]
			if apiHasFixedAttribute(api, attribute) {
				continue
			}
			if _, exists := known[attribute]; !exists {
				return fmt.Errorf("apis[%d].metrics.labels.%s references unknown authenticator attribute %q", i, label, attribute)
			}
		}
	}
	return nil
}

func hasRequestMetricLabels(apis []gatewayapi.API) bool {
	for _, api := range apis {
		if api.Metrics != nil && len(api.Metrics.Labels) > 0 {
			return true
		}
	}
	return false
}

func requestMetricLabelNames(apis []gatewayapi.API) []string {
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

func cloneObservabilityMetrics(m gatewayapi.ObservabilityMetrics) gatewayapi.ObservabilityMetrics {
	m.Enabled = clonePointer(m.Enabled)
	m.ScrapeInterval = clonePointer(m.ScrapeInterval)
	m.ScrapeTimeout = clonePointer(m.ScrapeTimeout)
	m.CustomMetricName = clonePointer(m.CustomMetricName)
	return m
}

func enabledObservabilityMetrics(m gatewayapi.ObservabilityMetrics) bool {
	return m.Enabled != nil && *m.Enabled
}

func validateObservabilityMetrics(m gatewayapi.ObservabilityMetrics) error {
	if err := validateCustomMetricName(m.CustomMetricName); err != nil {
		return err
	}
	for _, field := range []struct {
		Name  string
		Value *gatewayapi.Duration
	}{{"scrape_interval", m.ScrapeInterval}, {"scrape_timeout", m.ScrapeTimeout}} {
		name := "observability.metrics." + field.Name
		if err := validateDuration(name, field.Value, false); err != nil {
			return err
		}
		if time.Duration(*field.Value)%time.Millisecond != 0 {
			return fmt.Errorf("%s must be a whole number of milliseconds", name)
		}
	}
	if *m.ScrapeTimeout > *m.ScrapeInterval {
		return fmt.Errorf("observability.metrics.scrape_timeout (%s) must not exceed observability.metrics.scrape_interval (%s)", m.ScrapeTimeout, m.ScrapeInterval)
	}
	return nil
}

func requestMetricsLuaScript(apis []gatewayapi.API, counterName string) string {
	labels := requestMetricLabelNames(apis)
	quoted := make([]string, len(labels))
	for i, label := range labels {
		quoted[i] = strconv.Quote(label)
	}
	return "local labels = {" + strings.Join(quoted, ", ") + "}\n" +
		"local counter_name = " + strconv.Quote(counterName) + "\n\n" + requestMetricsLuaBody
}

func hasRequestMetricRoutes(hosts []*route.VirtualHost) bool {
	for _, host := range hosts {
		for _, route := range host.Routes {
			if route.Metadata != nil && route.Metadata.FilterMetadata[requestMetricsFilterName] != nil {
				return true
			}
		}
	}
	return false
}

func requestMetricsHTTPFilter(c resolvedConfig) (*hcm.HttpFilter, error) {
	metricConfig, err := packEnvoy(&lua.Lua{DefaultSourceCode: &core.DataSource{
		Specifier: &core.DataSource_InlineString{InlineString: requestMetricsLuaScript(c.APIs, requestMetricName(c.Config))},
	}})
	if err != nil {
		return nil, fmt.Errorf("encode request metrics Lua filter: %w", err)
	}
	return &hcm.HttpFilter{Name: requestMetricsFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: metricConfig}}, nil
}

func requestMetricsRouteMetadata(api gatewayapi.API) *structpb.Struct {
	labels := make(map[string]*structpb.Value, len(api.Metrics.Labels))
	for label, attribute := range api.Metrics.Labels {
		labels[label] = structpb.NewStringValue(attribute)
	}
	return &structpb.Struct{Fields: map[string]*structpb.Value{
		apiMetadataName: structpb.NewStringValue(api.Name),
		"labels":        structpb.NewStructValue(&structpb.Struct{Fields: labels}),
	}}
}

func requestMetricsStatsConfig(apis []gatewayapi.API, counterName string) *metrics.StatsConfig {
	fields := append([]string{apiMetadataName, requestMetricStatusLabelName}, requestMetricLabelNames(apis)...)
	prefix := `^http\.` + regexp.QuoteMeta(httpManagerStatPrefix) + `\.lua\.` + regexp.QuoteMeta(counterName)
	tags := make([]*metrics.TagSpecifier, 0, len(fields))
	for _, field := range fields {
		escaped := regexp.QuoteMeta(field)
		tags = append(tags, &metrics.TagSpecifier{
			TagName:  field,
			TagValue: &metrics.TagSpecifier_Regex{Regex: prefix + `(\|` + escaped + `=([^|]+))`},
		})
		prefix += `\|` + escaped + `=[^|]+`
	}
	return &metrics.StatsConfig{StatsTags: tags}
}
