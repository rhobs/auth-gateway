package config

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	metrics "github.com/envoyproxy/go-control-plane/envoy/config/metrics/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	requestMetricsFilterName        = "envoy.filters.http.lua"
	defaultRequestMetricCounterName = "auth_gateway_http_requests_total"
	requestMetricStatusLabelName    = "http_status_code"
)

var prometheusNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

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

func requestMetricsRouteMetadata(api API) *structpb.Struct {
	labels := make(map[string]*structpb.Value, len(api.Metrics.Labels))
	for label, attribute := range api.Metrics.Labels {
		labels[label] = structpb.NewStringValue(attribute)
	}
	return &structpb.Struct{Fields: map[string]*structpb.Value{
		apiMetadataName: structpb.NewStringValue(api.Name),
		"labels":        structpb.NewStructValue(&structpb.Struct{Fields: labels}),
	}}
}

func requestMetricsStatsConfig(apis []API, counterName string) *metrics.StatsConfig {
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

func requestMetricsLuaScript(apis []API, counterName string) string {
	labels := requestMetricLabelNames(apis)
	quoted := make([]string, len(labels))
	for i, label := range labels {
		quoted[i] = strconv.Quote(label)
	}
	return "local labels = {" + strings.Join(quoted, ", ") + "}\n" +
		"local counter_name = " + strconv.Quote(counterName) + "\n\n" + requestMetricsLuaBody
}

const requestMetricsLuaBody = `local function safe_label(value)
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
