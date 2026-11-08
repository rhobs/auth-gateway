package gateway

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/google/go-cmp/cmp"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	yaml "go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

var (
	updateGoldens = flag.Bool("update", false, "update generated reference files")
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
	config, err := Load(strings.NewReader(input))
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

func resolveTestConfig(t testing.TB, c gatewayapi.Config) resolvedConfig {
	t.Helper()
	effective, err := resolveConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	return effective
}

func assertGeneratedFilesEqual(t testing.TB, left, right GeneratedFiles) {
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

func generatedContentsByPath(t testing.TB, files GeneratedFiles, filePath string) []byte {
	t.Helper()
	for _, file := range files.All() {
		if file.Path == filePath {
			return file.Contents
		}
	}
	t.Fatalf("generated file %q is missing", filePath)
	return nil
}

func firstHTTPManager(t testing.TB, data []byte) *hcm.HttpConnectionManager {
	t.Helper()
	generated := decodeBootstrap(t, data)
	for _, chain := range generated.StaticResources.Listeners[0].FilterChains {
		manager := decodeHTTPManager(t, chain)
		if containsFilter(manager, "envoy.filters.http.jwt_authn") {
			return manager
		}
	}
	t.Fatal("no protected HTTP manager was generated")
	return nil
}

func httpFilterNames(manager *hcm.HttpConnectionManager) []string {
	names := make([]string, len(manager.HttpFilters))
	for i, filter := range manager.HttpFilters {
		names[i] = filter.Name
	}
	return names
}

func containsFilter(manager *hcm.HttpConnectionManager, name string) bool {
	for _, filter := range manager.HttpFilters {
		if filter.Name == name {
			return true
		}
	}
	return false
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

func decodeTLSSecret(t *testing.T, data []byte) *tls.Secret {
	t.Helper()
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode TLS secret YAML: %v", err)
	}
	resources, ok := document["resources"].([]any)
	if !ok || len(resources) != 1 {
		t.Fatalf("TLS SDS resources = %#v, want one resource", document["resources"])
	}
	resourceData, err := json.Marshal(resources[0])
	if err != nil {
		t.Fatalf("encode TLS SDS resource JSON: %v", err)
	}
	var resource anypb.Any
	if err := protojson.Unmarshal(resourceData, &resource); err != nil {
		t.Fatalf("decode packed TLS SDS resource: %v", err)
	}
	var secret tls.Secret
	if err := resource.UnmarshalTo(&secret); err != nil {
		t.Fatalf("decode TLS secret: %v", err)
	}
	return &secret
}

func namedRoute(routes []*route.Route, name string) *route.Route {
	for _, generated := range routes {
		if generated.Name == name {
			return generated
		}
	}
	return nil
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
