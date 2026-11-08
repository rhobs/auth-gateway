package otel

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPlaygroundOTelCollectorConfiguration(t *testing.T) {
	inputPath := filepath.Join("..", "..", "playground", "config.yaml")
	c := loadTestConfig(t, readTestFile(t, inputPath), inputPath)
	collectorConfig, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	checkReference(t, filepath.Join("..", "..", "playground", "otel-collector.yaml.golden"), collectorConfig)
}

var updateGoldens = flag.Bool("update", false, "update generated reference files")

func checkReference(t *testing.T, path string, generated []byte) {
	t.Helper()
	if *updateGoldens {
		if err := os.WriteFile(path, generated, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	reference, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	referenceLines := strings.Split(string(reference), "\n")
	generatedLines := strings.Split(string(generated), "\n")
	if diff := cmp.Diff(referenceLines, generatedLines); diff != "" {
		t.Errorf("%s is out of date; run make update-golden (-reference +generated):\n%s", path, diff)
	}
}
