package otel

import (
	"os"
	"strings"
	"testing"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	configuration "github.com/rhobs/auth-gateway/pkg/config"
)

func readTestFile(t testing.TB, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read test file %q: %v", name, err)
	}
	return string(data)
}

func loadTestConfig(t testing.TB, input, name string) gatewayapi.Config {
	t.Helper()
	config, err := configuration.Load(strings.NewReader(input))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return config
}
