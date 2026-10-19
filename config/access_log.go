package config

import (
	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	stream "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

func errorAccessLogs() ([]*accesslog.AccessLog, error) {
	fields := make(map[string]*structpb.Value)
	for key, value := range map[string]string{
		"timestamp":                  "%START_TIME%",
		"route":                      "%ROUTE_NAME%",
		"method":                     "%REQ(:METHOD)%",
		"path":                       "%REQ_WITHOUT_QUERY(:PATH)%",
		"status":                     "%RESPONSE_CODE%",
		"duration_ms":                "%DURATION%",
		"bytes_received":             "%BYTES_RECEIVED%",
		"bytes_sent":                 "%BYTES_SENT%",
		"response_flags":             "%RESPONSE_FLAGS%",
		"response_code_details":      "%RESPONSE_CODE_DETAILS%",
		"upstream_cluster":           "%UPSTREAM_CLUSTER%",
		"upstream_host":              "%UPSTREAM_HOST%",
		"upstream_transport_failure": "%UPSTREAM_TRANSPORT_FAILURE_REASON%",
		"connection_termination":     "%CONNECTION_TERMINATION_DETAILS%",
		"request_id":                 "%REQ(X-REQUEST-ID)%",
	} {
		fields[key] = structpb.NewStringValue(value)
	}
	config, err := packEnvoy(&stream.StdoutAccessLog{AccessLogFormat: &stream.StdoutAccessLog_LogFormat{LogFormat: &core.SubstitutionFormatString{
		Format: &core.SubstitutionFormatString_JsonFormat{JsonFormat: &structpb.Struct{Fields: fields}},
	}}})
	if err != nil {
		return nil, err
	}

	return []*accesslog.AccessLog{{
		Name:       "envoy.access_loggers.stdout",
		ConfigType: &accesslog.AccessLog_TypedConfig{TypedConfig: config},
		Filter: &accesslog.AccessLogFilter{FilterSpecifier: &accesslog.AccessLogFilter_StatusCodeFilter{
			StatusCodeFilter: &accesslog.StatusCodeFilter{Comparison: &accesslog.ComparisonFilter{
				Op:    accesslog.ComparisonFilter_GE,
				Value: &core.RuntimeUInt32{DefaultValue: 400},
			}},
		}},
	}}, nil
}
