package config

import (
	"math"
	"strings"
	"testing"
	"time"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
)

func TestLoadAPIAdmissionControl(t *testing.T) {
	c := loadConfigCase(t, "admission-control")
	want := &gatewayapi.AdmissionControlConfig{
		Enabled: true, SamplingWindow: duration(45 * time.Second), SrThreshold: new(91.5),
		RPSThreshold: new(uint32(25)), MaxRejectionProbability: new(65.0),
	}
	assertConfigDiff(t, "API admission control", want, c.APIs[0].AdmissionControl)
	assertConfigDiff(t, "default tuning", &gatewayapi.AdmissionControlConfig{Enabled: true}, c.APIs[1].AdmissionControl)
	if c.APIs[2].AdmissionControl != nil {
		t.Fatal("unconfigured API gained admission control")
	}
	if c.APIs[3].AdmissionControl.Enabled {
		t.Fatal("omitted enabled field opted an API into admission control")
	}
}

func TestLoadEmptyAdmissionControlDefaultsOff(t *testing.T) {
	input := `version: 1
servers:
  - hostname: admission.test
    apis: [plain]
apis:
  - name: plain
    admission_control: {}
    upstream: {address: httpbin, port: 8080}
    routes:
      - methods: [GET]
        path: {exact: /plain}
`
	c, err := Load(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	assertConfigDiff(t, "empty admission block", &gatewayapi.AdmissionControlConfig{}, c.APIs[0].AdmissionControl)
}

func TestAdmissionControlRejectsInvalidSettings(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		edit  func(*gatewayapi.AdmissionControlConfig)
	}{
		{name: "zero window", field: "sampling_window", edit: func(c *gatewayapi.AdmissionControlConfig) { c.SamplingWindow = duration(0) }},
		{name: "negative window", field: "sampling_window", edit: func(c *gatewayapi.AdmissionControlConfig) { c.SamplingWindow = duration(-time.Second) }},
		{name: "negative success rate", field: "sr_threshold", edit: func(c *gatewayapi.AdmissionControlConfig) { c.SrThreshold = new(-1.0) }},
		{name: "success rate above 100", field: "sr_threshold", edit: func(c *gatewayapi.AdmissionControlConfig) { c.SrThreshold = new(100.1) }},
		{name: "NaN success rate", field: "sr_threshold", edit: func(c *gatewayapi.AdmissionControlConfig) { c.SrThreshold = new(math.NaN()) }},
		{name: "infinite success rate", field: "sr_threshold", edit: func(c *gatewayapi.AdmissionControlConfig) { c.SrThreshold = new(math.Inf(1)) }},
		{name: "negative rejection probability", field: "max_rejection_probability", edit: func(c *gatewayapi.AdmissionControlConfig) { c.MaxRejectionProbability = new(-1.0) }},
		{name: "rejection probability above 100", field: "max_rejection_probability", edit: func(c *gatewayapi.AdmissionControlConfig) { c.MaxRejectionProbability = new(100.1) }},
		{name: "NaN rejection probability", field: "max_rejection_probability", edit: func(c *gatewayapi.AdmissionControlConfig) { c.MaxRejectionProbability = new(math.NaN()) }},
		{name: "infinite rejection probability", field: "max_rejection_probability", edit: func(c *gatewayapi.AdmissionControlConfig) { c.MaxRejectionProbability = new(math.Inf(-1)) }},
		{name: "invalid disabled policy", field: "sampling_window", edit: func(c *gatewayapi.AdmissionControlConfig) {
			c.Enabled = false
			c.SamplingWindow = duration(0)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := loadConfigCase(t, "admission-control")
			test.edit(c.APIs[0].AdmissionControl)
			field := "apis[0].admission_control." + test.field
			if err := Validate(c); err == nil || !strings.Contains(err.Error(), field) {
				t.Fatalf("validation error = %v, want field %s", err, field)
			}
		})
	}
}

func TestAdmissionControlDefaultsCloneInput(t *testing.T) {
	c := loadConfigCase(t, "admission-control")
	defaulted := withDefaultsConfig(c)
	policy := defaulted.APIs[0].AdmissionControl
	policy.Enabled = false
	*policy.SamplingWindow = gatewayapi.Duration(time.Minute)
	*policy.SrThreshold = 90
	*policy.RPSThreshold = 10
	*policy.MaxRejectionProbability = 80
	want := &gatewayapi.AdmissionControlConfig{
		Enabled: true, SamplingWindow: duration(45 * time.Second), SrThreshold: new(91.5),
		RPSThreshold: new(uint32(25)), MaxRejectionProbability: new(65.0),
	}
	assertConfigDiff(t, "original admission policy", want, c.APIs[0].AdmissionControl)
}
