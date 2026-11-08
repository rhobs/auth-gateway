package api_test

import (
	"fmt"
	"log"
	"time"

	"github.com/rhobs/auth-gateway/pkg/api"
	"github.com/rhobs/auth-gateway/pkg/config"
)

func ExampleNewDuration() {
	gateway := api.Config{
		Version: 1,
		Listener: api.Listener{
			Port:           new(uint32(8080)),
			RequestTimeout: api.NewDuration(30 * time.Second),
		},
		Servers: []api.Server{{
			Hostname: "metrics.example.com",
			APIs:     []string{"metrics"},
		}},
		APIs: []api.API{{
			Name: "metrics",
			Upstream: api.Upstream{
				Address:        "thanos-receive",
				Port:           19291,
				ConnectTimeout: api.NewDuration(5 * time.Second),
			},
			Routes: []api.Route{{
				Methods: []string{"POST"},
				Path:    api.PathMatch{Exact: "/metrics/api/v1/receive"},
			}},
		}},
	}
	if err := config.Validate(gateway); err != nil {
		log.Fatal(err)
	}

	fmt.Println(gateway.Listener.RequestTimeout)
	fmt.Println(gateway.APIs[0].Upstream.ConnectTimeout)
	// Output:
	// 30s
	// 5s
}
