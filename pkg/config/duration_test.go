package config

import (
	"strings"
	"testing"
	"time"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func duration(value time.Duration) *gatewayapi.Duration { return new(gatewayapi.Duration(value)) }

func TestDurationErrorIncludesFieldPath(t *testing.T) {
	if _, err := Load(strings.NewReader(readFixture(t, "jwks-duration-invalid.yaml"))); err == nil || !strings.Contains(err.Error(), "authenticators[0].jwt.jwks.fetch_timeout") {
		t.Fatalf("duration field error = %v, want the complete field path", err)
	}
}
