package config

import (
	"testing"

	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	stream "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
)

func TestGeneratedErrorAccessLogUsesQueryFreePath(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	generated := decodeBootstrap(t, files.EnvoyBootstrap.Contents)
	manager := decodeHTTPManager(t, generated.StaticResources.Listeners[0].FilterChains[0])
	logs := manager.GetAccessLog()
	if len(logs) != 1 {
		t.Fatalf("access logs = %d, want one", len(logs))
	}
	comparison := logs[0].GetFilter().GetStatusCodeFilter().GetComparison()
	if comparison.GetOp() != accesslog.ComparisonFilter_GE || comparison.GetValue().GetDefaultValue() != 400 {
		t.Fatalf("error access log status filter = %v, want >= 400", comparison)
	}
	var stdout stream.StdoutAccessLog
	if err := logs[0].GetTypedConfig().UnmarshalTo(&stdout); err != nil {
		t.Fatal(err)
	}
	format := stdout.GetLogFormat().GetJsonFormat()
	if format == nil {
		t.Fatal("error access log has no JSON format")
	}
	if got := format.GetFields()["path"].GetStringValue(); got != "%PATH(NQ)%" {
		t.Fatalf("error access log path format = %q, want %%PATH(NQ)%%", got)
	}
}
