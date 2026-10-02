//go:build e2e

package e2e

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rhobs/auth-gateway/e2e/internal/framework"
)

func TestGatewayE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Auth Gateway E2E", Label("e2e", "auth-gateway"))
}

var _ = BeforeSuite(func() {
	var err error
	env, err = framework.New()
	Expect(err).NotTo(HaveOccurred())
})

var _ = ReportAfterEach(func(report SpecReport) {
	if report.Failed() {
		env.Diagnostics(activeNamespace)
	}
})
