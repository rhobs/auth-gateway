# RHOBS Auth Gateway

RHOBS Auth Gateway is a Go library that loads one YAML configuration and
generates Envoy files or Kubernetes resources. It does not run Envoy or a
controller.

The supported features include exact-host routing, HTTP and HTTPS listeners,
HTTP/1 and HTTP/2 upstreams, JWT and API-key authentication, attribute-based
authorization, request header mapping, per-API response counters, access logs,
Prometheus metrics, and OpenTelemetry traces. Client-certificate mTLS is not
supported.

## Requirements

Importing this module requires Go 1.26 or later. The module is pre-v1.0 and
does not promise a stable Go API. The YAML schema accepts only `version: 1`;
the loader rejects unknown fields and extra YAML documents and does not migrate
older formats.

## Generate configuration

Install the module:

```sh
go get github.com/rhobs/auth-gateway
```

Load and generate files or a Kubernetes manifest from Go:

```go
package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/rhobs/auth-gateway/config"
)

func main() {
	gateway, err := config.Load(strings.NewReader(`version: 1
servers:
  - hostname: status.example.com
    apis: [status]
apis:
  - name: status
    upstream: {address: httpbin, port: 8080}
    routes:
      - methods: [GET]
        path: {exact: /status}
kubernetes:
  name: auth-gateway
  namespace: observability
`))
	if err != nil {
		log.Fatal(err)
	}

	files, err := config.Generate(gateway)
	if err != nil {
		log.Fatal(err)
	}
	resources, err := config.GenerateKubernetes(gateway)
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

`config.Generate` returns Envoy files with their required paths. It does not
need Kubernetes settings. `config.GenerateKubernetes` requires a `kubernetes`
section and returns typed resources. Neither call contacts a cluster or creates
the referenced namespace, TLS Secrets, API-key Secret, or CA ConfigMaps. Create
those resources first, then apply the manifest.

The [full configuration example](config.example.yaml) covers the supported
schema and comments optional settings and defaults. The
[configuration reference](docs/configuration-reference.md) lists every field,
default, and validation rule. Empty Kubernetes image values use the pinned Go
defaults documented there; set image fields to use approved images or mirrors.

For file-based API-key deployments, omit `api_key.secret` and provide the
separate API-key ECDS file. See the [API-key guide](docs/auth/api-key.md) for
the credential format.

## Gateway behavior

Each server binds one exact hostname to an ordered list of APIs. API routes use
an exact path, prefix, or regular expression. A matching path with an
unsupported method returns `405`; an unknown host or path returns `404`.
HTTPS uses SNI to select a certificate and then checks the request host.

JWTs and API keys authenticate independently. Authorization grants name the
authenticator, APIs, and allowed attribute values. Attribute mappings affect
upstream headers and metric labels; grants check the original values. See the
[JWT guide](docs/auth/jwt.md), [API-key guide](docs/auth/api-key.md), and
[Envoy behavior guide](docs/envoy.md) for request and update behavior.

Mapping changes update the separate ECDS processing ConfigMap. API-key changes
update the Secret. Downstream certificate changes reload through SDS. Static
Envoy configuration changes require an explicit Deployment rollout; the
generated Deployment has no checksum annotation.

## Local playground

The Docker Compose demo exercises public, JWT, API-key, and mixed-auth servers
with mock OAuth, httpbin, metrics, and traces. Start with
[playground/README.md](playground/README.md).

## Development and contributions

Develop feature changes on a branch and submit them to the upstream repository
through a pull request for review. See [CONTRIBUTING.md](CONTRIBUTING.md) for
the contribution workflow, checks, and golden-file updates.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
