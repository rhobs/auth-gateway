package config

import (
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func duration(value time.Duration) *Duration { return new(Duration(value)) }

func TestDurationYAMLContract(t *testing.T) {
	for _, value := range []string{"250ms", "5s", "5m", "1.5ms", "0s"} {
		var parsed Duration
		if err := yaml.Unmarshal([]byte(value), &parsed); err != nil {
			t.Fatalf("parse %q: %v", value, err)
		}
		encoded, err := yaml.Marshal(&parsed)
		if err != nil {
			t.Fatal(err)
		}
		var roundtrip Duration
		if err := yaml.Unmarshal(encoded, &roundtrip); err != nil || parsed != roundtrip {
			t.Fatalf("duration roundtrip %q: %v, %v", value, roundtrip, err)
		}
	}

	for name, input := range map[string]string{
		"number":     "5",
		"empty":      `""`,
		"negative":   "-1s",
		"sub-ms":     "500us",
		"overflow":   "999999999999h",
		"non-scalar": "[5s]",
	} {
		t.Run(name, func(t *testing.T) {
			var parsed Duration
			if err := yaml.Unmarshal([]byte(input), &parsed); err == nil {
				t.Fatalf("duration %s was accepted", input)
			}
		})
	}

	if _, err := Load(strings.NewReader(readFixture(t, "jwks-duration-invalid.yaml"))); err == nil || !strings.Contains(err.Error(), "authenticators[0].jwt.jwks.fetch_timeout") {
		t.Fatalf("duration field error = %v, want the complete field path", err)
	}
}
