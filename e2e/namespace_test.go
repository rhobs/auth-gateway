//go:build e2e

package e2e

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
)

func TestCurrentE2ERunIDUsesEnvironmentOrProcess(t *testing.T) {
	t.Setenv(e2eRunIDEnvironmentVariable, "custom-run")
	if got := currentE2ERunID(); got != "custom-run" {
		t.Fatalf("configured run ID = %q, want custom-run", got)
	}

	t.Setenv(e2eRunIDEnvironmentVariable, "")
	first := currentE2ERunID()
	second := currentE2ERunID()
	if first == second {
		t.Fatalf("fallback run IDs collided: %q", first)
	}
	for _, runID := range []string{first, second} {
		if len(runID) != 17 || runID[0] != 'r' {
			t.Errorf("fallback run ID = %q, want r-prefixed 16-character hex ID", runID)
		}
	}
}

func TestE2ENamespacesAreScopedToEachRun(t *testing.T) {
	const base = "auth-gateway-header-attributes-e2e"
	firstRun := namespaceForE2ERun(base, "r1760208233-71234")
	secondRun := namespaceForE2ERun(base, "r1760208233-71235")

	if firstRun == secondRun {
		t.Fatalf("concurrent e2e runs share namespace %q", firstRun)
	}
	for _, name := range []string{firstRun, secondRun} {
		if problems := validation.IsDNS1123Label(name); len(problems) > 0 {
			t.Errorf("namespace %q is invalid: %v", name, problems)
		}
		label := "namespace-" + name
		if problems := validation.IsValidLabelValue(label); len(problems) > 0 {
			t.Errorf("namespace label %q is invalid: %v", label, problems)
		}
	}
}

func TestE2ENamespaceRegistrationRejectsSharedScenarioNamespaces(t *testing.T) {
	const runID = "r1760208233-71234"
	registry := make(map[string]string)
	first, err := registerE2ENamespace(registry, "auth-gateway-routing-e2e", runID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := registerE2ENamespace(registry, "auth-gateway-routing-e2e", runID)
	if err == nil || !strings.Contains(err.Error(), "shared by scenarios") {
		t.Fatalf("duplicate scenario registration error = %v, want shared namespace error", err)
	}
	if second != "" {
		t.Fatalf("duplicate scenario namespace = %q, want empty result", second)
	}
	if first == "" {
		t.Fatal("first scenario namespace is empty")
	}
}

func TestE2ENamespaceSupportsLongestScenarioWithMaximumDefaultRunID(t *testing.T) {
	const base = "auth-gateway-header-attributes-e2e"
	const runID = "rffffffffffffffff"
	name := namespaceForE2ERun(base, runID)
	if problems := validation.IsDNS1123Label(name); len(problems) > 0 {
		t.Fatalf("namespace %q is invalid: %v", name, problems)
	}
	label := "namespace-" + name
	if problems := validation.IsValidLabelValue(label); len(problems) > 0 {
		t.Fatalf("namespace label %q is invalid: %v", label, problems)
	}
}
