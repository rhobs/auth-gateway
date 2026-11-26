# Auth Gateway

Auth Gateway is an API for configuring Envoy Proxy as an authentication and
authorization proxy, primarily for observability workloads. It also suits other
APIs with simple access patterns, such as reading or writing a resource.

It uses attribute-based access control (ABAC), deriving attributes throughout
the request lifecycle for authorization, upstream headers, and further processing.

The API is provided as a Go library that loads YAML and generates Envoy files
or Kubernetes resources. It does not run Envoy or a controller.

## Table of contents

- [Gateway behavior](#gateway-behavior)
- [Requirements](#requirements)
- [Generate configuration](#generate-configuration)
- [Local playground](#local-playground)
- [Development and contributions](#development-and-contributions)
- [License](#license)

## Gateway behavior

The gateway matches a request to a server by hostname, then to an API route by
method and path. The server's API binding defines who can use it. Protected
requests must pass authentication and authorization before reaching the upstream.

- [Gateway concepts](docs/concepts.md) explains how servers, APIs, authenticators,
  attributes, and access rules fit together.
- [Expressions and keywords](docs/expressions.md) lists the operations, source
  types, and configuration choices available at each layer.
- [Authentication and authorization](docs/auth/README.md) covers credentials,
  attribute-based access rules, and forwarding attributes to upstream headers.
- [Traffic protection](docs/traffic-protection.md) covers circuit breakers,
  admission control, overload protection, and timeouts.
- [Logs, metrics, and traces](docs/envoy.md#logs-metrics-and-traces) describes
  how to observe gateway traffic.
- [Fault injection](docs/fault-injection.md) covers controlled HTTP errors for
  SLO tests.
- [Deployment and updates](docs/envoy.md#files-and-reloads) explains required
  external resources, live reloads, and when to roll out the Deployment.

## Requirements

Importing this module requires Go 1.26 or later.

## Generate configuration

Install the module:

```sh
go get github.com/rhobs/auth-gateway
```

The public configuration structs live in `pkg/api/types.go`. `pkg/gateway`
loads and validates the API and generates Envoy files, Kubernetes resources,
and collector configuration. Feature code and unit tests share matching file
names, with one fixture tree under `pkg/gateway/testdata`.

Load and generate files or a Kubernetes manifest from Go:

```go
package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/rhobs/auth-gateway/pkg/gateway"
)

func main() {
	cfg, err := gateway.Load(strings.NewReader(`version: 1
servers:
  - hostname: status.example.com
    apis:
      - name: status
        public: true
apis:
  - name: status
    upstream: {address: httpbin, port: 8080}
    routes:
      - methods: [GET]
        path: {expression: equals, value: /status}
kubernetes:
  name: auth-gateway
  namespace: observability
`))
	if err != nil {
		log.Fatal(err)
	}

	files, err := gateway.Generate(cfg)
	if err != nil {
		log.Fatal(err)
	}
	resources, err := gateway.GenerateKubernetes(cfg)
	if err != nil {
		log.Fatal(err)
	}
	manifest, err := resources.YAML()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(files.EnvoyBootstrap.Path)
	fmt.Print(string(manifest))
}
```

`gateway.Generate` returns Envoy files with their required paths. It does not
need Kubernetes settings. `gateway.GenerateKubernetes` requires a `kubernetes`
section and returns typed resources. Neither call contacts a cluster or creates
the referenced namespace, TLS Secrets, API-key Secret, or CA ConfigMaps. Create
those resources first, then apply the manifest.

The [full configuration example](config.example.yaml) covers the supported
schema and comments optional settings and defaults. The
[configuration reference](docs/configuration-reference.md) lists every field,
default, and validation rule. Empty Kubernetes image values use the pinned Go
defaults documented there; set image fields to use approved images or mirrors.

For file-based API-key deployments, omit `api_key.secret` and provide the
separate API-key ECDS file. mTLS deployments must provide the configured client
CA bundle. See the [API-key guide](docs/auth/api-key.md) for the credential
format and the [mTLS guide](docs/auth/mtls.md) for client certificate setup.

## Local playground

The Docker Compose demo exercises public, JWT, API-key, and tenant-selected access
with mock OAuth, httpbin, metrics, and traces. Start with
[playground/README.md](playground/README.md).

## Development and contributions

Develop feature changes on a branch and submit them to the upstream repository
through a pull request for review. See [CONTRIBUTING.md](CONTRIBUTING.md) for
the contribution workflow, checks, and golden-file updates.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
