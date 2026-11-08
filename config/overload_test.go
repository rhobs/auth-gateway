package config

import (
	"math"
	"strings"
	"testing"
)

func TestValidateRejectsInvalidOverloadConfiguration(t *testing.T) {
	exampleConfig := readFixture(t, "public-routing/config.yaml")
	validOverload := func() *OverloadConfig {
		return &OverloadConfig{
			MaxHeapBytes:             128 << 20,
			MaxDownstreamConnections: 1024,
			HeapShrinkThreshold:      new(0.70),
			RequestRejectThreshold:   new(0.85),
		}
	}
	tests := []struct {
		name string
		want string
		edit func(*Config)
	}{
		{name: "zero max downstream connections", want: "overload.max_downstream_connections", edit: func(c *Config) {
			o := validOverload()
			o.MaxDownstreamConnections = 0
			c.Overload = o
		}},
		{name: "heap shrink threshold not finite", want: "overload.heap_shrink_threshold", edit: func(c *Config) {
			o := validOverload()
			o.HeapShrinkThreshold = new(math.NaN())
			c.Overload = o
		}},
		{name: "heap shrink threshold out of range", want: "overload.heap_shrink_threshold", edit: func(c *Config) {
			o := validOverload()
			o.HeapShrinkThreshold = new(0.0)
			c.Overload = o
		}},
		{name: "request reject threshold out of range", want: "overload.request_reject_threshold", edit: func(c *Config) {
			o := validOverload()
			o.RequestRejectThreshold = new(1.0)
			c.Overload = o
		}},
		{name: "shrink threshold not below reject threshold", want: "overload.heap_shrink_threshold must be less than overload.request_reject_threshold", edit: func(c *Config) {
			o := validOverload()
			o.HeapShrinkThreshold = new(0.90)
			o.RequestRejectThreshold = new(0.80)
			c.Overload = o
		}},
		{name: "missing kubernetes memory limit", want: "overload requires a positive kubernetes.resources.limits.memory", edit: func(c *Config) {
			c.Overload = validOverload()
			c.Kubernetes.Resources.Limits = map[string]string{}
		}},
		{name: "heap budget exceeds memory limit", want: "overload.max_heap_bytes", edit: func(c *Config) {
			o := validOverload()
			o.MaxHeapBytes = 512 << 20
			c.Overload = o
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := loadTestConfig(t, exampleConfig, "valid baseline")
			test.edit(&config)
			if err := config.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestOptInOverloadDefaults(t *testing.T) {
	c := loadConfigCase(t, "public-routing")
	c.Overload = &OverloadConfig{MaxHeapBytes: 201326592, MaxDownstreamConnections: 2048}
	resolved, err := resolveConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	want := &OverloadConfig{MaxHeapBytes: 201326592, MaxDownstreamConnections: 2048, HeapShrinkThreshold: new(0.90), RequestRejectThreshold: new(0.95)}
	assertConfigDiff(t, "overload defaults", want, resolved.Overload)
	if c.Overload.HeapShrinkThreshold != nil {
		t.Error("default resolution added heap_shrink_threshold to the caller's configuration")
	}
	if c.Overload.RequestRejectThreshold != nil {
		t.Error("default resolution added request_reject_threshold to the caller's configuration")
	}
}
