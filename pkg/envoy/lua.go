package envoy

import (
	"fmt"
	"strconv"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	lua "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
)

const (
	requestMetricsFilterName = "envoy.filters.http.lua"
	requestMetricsLuaBody    = `local function safe_label(value)
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

func requestMetricsLuaScript(apis []gatewayapi.API, counterName string) string {
	labels := configuration.RequestMetricLabelNames(apis)
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

func requestMetricsHTTPFilter(c configuration.ResolvedConfig) (*hcm.HttpFilter, error) {
	metricConfig, err := packEnvoy(&lua.Lua{DefaultSourceCode: &core.DataSource{
		Specifier: &core.DataSource_InlineString{InlineString: requestMetricsLuaScript(c.APIs, configuration.RequestMetricNameConfig(c.Config))},
	}})
	if err != nil {
		return nil, fmt.Errorf("encode request metrics Lua filter: %w", err)
	}
	return &hcm.HttpFilter{Name: requestMetricsFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: metricConfig}}, nil
}
