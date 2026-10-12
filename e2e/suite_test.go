//go:build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/rhobs/auth-gateway/e2e/internal/framework"
)

const e2eRunIDEnvironmentVariable = "AUTH_GATEWAY_E2E_RUN_ID"

// Parallel Ginkgo workers inherit one run ID; separate runner processes get separate namespaces.
var e2eRunID = currentE2ERunID()

var e2eNamespaceRegistry = struct {
	sync.Mutex
	bases map[string]string
}{bases: make(map[string]string)}

func TestGatewayE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Auth Gateway E2E", Label("e2e", "auth-gateway"))
}

// backgroundNamespaceCleanup tracks namespace deletions started with
// deleteNamespaceInBackground so AfterSuite can confirm they all finished without
// making every container's teardown wait on Kubernetes actually removing the
// namespace. Errors are collected rather than asserted inline because a goroutine
// outliving its spec must not attribute a Ginkgo failure to whatever spec happens to
// be running when it completes.
var backgroundNamespaceCleanup struct {
	sync.Mutex
	sync.WaitGroup
	errs []error
}

func deleteNamespaceInBackground(namespace string) {
	wait, err := env.DeleteNamespaceAsync(context.Background(), namespace, 120*time.Second)
	if err != nil {
		backgroundNamespaceCleanup.Lock()
		backgroundNamespaceCleanup.errs = append(backgroundNamespaceCleanup.errs, err)
		backgroundNamespaceCleanup.Unlock()
		return
	}
	backgroundNamespaceCleanup.Add(1)
	go func() {
		defer backgroundNamespaceCleanup.Done()
		if err := wait(); err != nil {
			backgroundNamespaceCleanup.Lock()
			backgroundNamespaceCleanup.errs = append(backgroundNamespaceCleanup.errs, err)
			backgroundNamespaceCleanup.Unlock()
		}
	}()
}

var _ = AfterSuite(func() {
	backgroundNamespaceCleanup.Wait()
	Expect(backgroundNamespaceCleanup.errs).To(BeEmpty(), "background namespace cleanup")
})

func currentE2ERunID() string {
	if runID := os.Getenv(e2eRunIDEnvironmentVariable); runID != "" {
		return runID
	}
	var entropy [8]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		panic(fmt.Errorf("generate e2e run ID: %w", err))
	}
	return "r" + hex.EncodeToString(entropy[:])
}

func e2eNamespace(base string) string {
	e2eNamespaceRegistry.Lock()
	defer e2eNamespaceRegistry.Unlock()

	name, err := registerE2ENamespace(e2eNamespaceRegistry.bases, base, e2eRunID)
	if err != nil {
		panic(err)
	}
	return name
}

func registerE2ENamespace(registry map[string]string, base, runID string) (string, error) {
	name := namespaceForE2ERun(base, runID)
	if registeredBase, exists := registry[name]; exists {
		return "", fmt.Errorf("e2e namespace %q is shared by scenarios %q and %q", name, registeredBase, base)
	}
	registry[name] = base
	return name, nil
}

// namespaceForE2ERun keeps test resources and their diagnostic labels below Kubernetes' name limits.
func namespaceForE2ERun(base, runID string) string {
	name := base + "-" + runID
	if problems := validation.IsDNS1123Label(name); len(problems) > 0 {
		panic(fmt.Sprintf("invalid e2e namespace %q: %s", name, strings.Join(problems, ", ")))
	}
	label := "namespace-" + name
	if problems := validation.IsValidLabelValue(label); len(problems) > 0 {
		panic(fmt.Sprintf("invalid e2e namespace label %q: %s", label, strings.Join(problems, ", ")))
	}
	return name
}

var _ = BeforeSuite(func() {
	var err error
	env, err = framework.New()
	Expect(err).NotTo(HaveOccurred())
})

var _ = ReportAfterEach(func(report SpecReport) {
	if report.Failed() {
		env.Diagnostics(specNamespace(report))
	}
})

func specNamespace(report SpecReport) string {
	for _, label := range report.Labels() {
		if strings.HasPrefix(label, "namespace-") {
			return strings.TrimPrefix(label, "namespace-")
		}
	}
	return ""
}
