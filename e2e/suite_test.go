//go:build e2e

package e2e

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestGatewayE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Auth Gateway E2E", Label("e2e", "auth-gateway"))
}
