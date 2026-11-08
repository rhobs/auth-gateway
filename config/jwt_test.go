package config

import (
	"strings"
	"testing"
	"time"
)

func TestJWKSFetchTimeoutDefaultsForNull(t *testing.T) {
	c, err := Load(strings.NewReader(readFixture(t, "jwks-duration-null.yaml")))
	if err != nil || *c.Authenticators[0].JWT.JWKS.FetchTimeout != Duration(5*time.Second) {
		t.Fatalf("null fetch timeout default: %v", err)
	}
}
