package config_test

import (
	"fmt"
	"log"
	"strings"

	"github.com/rhobs/auth-gateway/pkg/config"
)

const exampleGatewayYAML = `version: 1
servers:
  - hostname: auth.example.com
    apis: [metrics]
apis:
  - name: metrics
    upstream:
      address: thanos-receive
      port: 19291
    routes:
      - methods: [POST]
        path:
          exact: /metrics/api/v1/receive
`

func ExampleLoad() {
	gateway, err := config.Load(strings.NewReader(exampleGatewayYAML))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(gateway.APIs[0].Name)
	// Output: metrics
}
