package envoy

import (
	"regexp"

	metrics "github.com/envoyproxy/go-control-plane/envoy/config/metrics/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	"google.golang.org/protobuf/types/known/structpb"
)

func requestMetricsRouteMetadata(api gatewayapi.API) *structpb.Struct {
	labels := make(map[string]*structpb.Value, len(api.Metrics.Labels))
	for label, attribute := range api.Metrics.Labels {
		labels[label] = structpb.NewStringValue(attribute)
	}
	return &structpb.Struct{Fields: map[string]*structpb.Value{
		configuration.ApiMetadataName: structpb.NewStringValue(api.Name),
		"labels":                      structpb.NewStructValue(&structpb.Struct{Fields: labels}),
	}}
}

func requestMetricsStatsConfig(apis []gatewayapi.API, counterName string) *metrics.StatsConfig {
	fields := append([]string{configuration.ApiMetadataName, configuration.RequestMetricStatusLabelName}, configuration.RequestMetricLabelNames(apis)...)
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
