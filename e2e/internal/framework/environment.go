//go:build e2e

package framework

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
)

const defaultClusterContext = "kind-auth-gateway-e2e"

// Environment scopes Kubernetes clients and fixture paths to one cluster.
type Environment struct {
	Root           string
	ClusterContext string

	config   *rest.Config
	client   kubernetes.Interface
	dynamic  dynamic.Interface
	mapper   *restmapper.DeferredDiscoveryRESTMapper
	mapperMu sync.Mutex
}

func New() (*Environment, error) {
	root, err := Root()
	if err != nil {
		return nil, err
	}
	clusterContext := os.Getenv("AUTH_GATEWAY_E2E_CONTEXT")
	if clusterContext == "" {
		clusterContext = defaultClusterContext
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{CurrentContext: clusterContext},
	)
	config, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load Kubernetes context %q: %w", clusterContext, err)
	}
	config = rest.CopyConfig(config)
	config.Timeout = 20 * time.Second

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create dynamic Kubernetes client: %w", err)
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes discovery client: %w", err)
	}

	return &Environment{
		Root:           root,
		ClusterContext: clusterContext,
		config:         config,
		client:         client,
		dynamic:        dynamicClient,
		mapper:         restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(discoveryClient)),
	}, nil
}

// Root finds the repository root from the current directory or one of its parents.
func Root() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		fixture := filepath.Join(dir, "e2e", "fixtures", "gateway.yaml")
		if info, err := os.Stat(fixture); err == nil && !info.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("run from the repository or e2e directory")
		}
		dir = parent
	}
}

func (e *Environment) KubeContext() string {
	if e.ClusterContext == "" {
		return defaultClusterContext
	}
	return e.ClusterContext
}

func (e *Environment) Fixture(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(e.Root, "e2e", "fixtures", name))
}

func (e *Environment) StatePath(parts ...string) string {
	return filepath.Join(append([]string{e.Root, "e2e", ".state", e.KubeContext()}, parts...)...)
}
