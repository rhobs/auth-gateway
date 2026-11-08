package kubernetes

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/google/go-cmp/cmp"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
	envoyimpl "github.com/rhobs/auth-gateway/pkg/envoy"
	yaml "go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
)

func duration(value time.Duration) *gatewayapi.Duration { return new(gatewayapi.Duration(value)) }

func readTestFile(t testing.TB, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read test file %q: %v", name, err)
	}
	return string(data)
}

func readFixture(t testing.TB, name string) string {
	t.Helper()
	return readTestFile(t, filepath.Join("testdata", name))
}

func loadTestConfig(t testing.TB, input, name string) gatewayapi.Config {
	t.Helper()
	config, err := configuration.Load(strings.NewReader(input))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return config
}

func loadConfigCase(t testing.TB, name string) gatewayapi.Config {
	t.Helper()
	return loadTestConfig(t, readFixture(t, filepath.Join(name, "config.yaml")), name+" case")
}

func loadAuthValidationFixture(t testing.TB) gatewayapi.Config {
	t.Helper()
	return loadTestConfig(t, readFixture(t, filepath.Join("baselines", "auth-validation.yaml")), "auth validation fixture")
}

func assertConfigDiff(t testing.TB, name string, want, got any) {
	t.Helper()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("%s mismatch (-want +got):\n%s", name, diff)
	}
}

func resourceMap(entries []struct{ name, value string }, reverse bool) map[string]string {
	values := make(map[string]string, len(entries))
	for i := range entries {
		index := i
		if reverse {
			index = len(entries) - i - 1
		}
		values[entries[index].name] = entries[index].value
	}
	return values
}

func assertGeneratedFilesEqual(t testing.TB, left, right envoyimpl.GeneratedFiles) {
	t.Helper()
	leftFiles := left.All()
	rightFiles := right.All()
	if len(leftFiles) != len(rightFiles) {
		t.Fatalf("generated file counts differ: %d and %d", len(leftFiles), len(rightFiles))
	}
	for i, file := range leftFiles {
		other := rightFiles[i]
		if file.Path != other.Path || !bytes.Equal(file.Contents, other.Contents) {
			t.Fatalf("generated file %q differs from %q", file.Path, other.Path)
		}
	}
}

func decodeHTTPManager(t testing.TB, chain *listener.FilterChain) *hcm.HttpConnectionManager {
	t.Helper()
	var manager hcm.HttpConnectionManager
	if err := chain.Filters[0].GetTypedConfig().UnmarshalTo(&manager); err != nil {
		t.Fatal(err)
	}
	return &manager
}

func decodeBootstrap(t testing.TB, data []byte) *bootstrap.Bootstrap {
	t.Helper()
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode YAML: %v", err)
	}
	jsonData, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode JSON: %v", err)
	}
	var config bootstrap.Bootstrap
	if err := protojson.Unmarshal(jsonData, &config); err != nil {
		t.Fatalf("decode Envoy bootstrap: %v", err)
	}
	return &config
}
