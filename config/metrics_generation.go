package config

import (
	"regexp"

	metrics "github.com/envoyproxy/go-control-plane/envoy/config/metrics/v3"
)

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
