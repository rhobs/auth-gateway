package config

import (
	"fmt"
	"math"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	admissioncontrol "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/admission_control/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const admissionControlFilterName = "envoy.filters.http.admission_control"

// AdmissionControlConfig enables Envoy admission control for one API.
type AdmissionControlConfig struct {
	Enabled                 bool      `yaml:"enabled,omitempty"`
	SamplingWindow          *Duration `yaml:"sampling_window,omitempty"`
	SrThreshold             *float64  `yaml:"sr_threshold,omitempty"`
	RPSThreshold            *uint32   `yaml:"rps_threshold,omitempty"`
	MaxRejectionProbability *float64  `yaml:"max_rejection_probability,omitempty"`
}

func (c AdmissionControlConfig) clone() AdmissionControlConfig {
	c.SamplingWindow = clonePointer(c.SamplingWindow)
	c.SrThreshold = clonePointer(c.SrThreshold)
	c.RPSThreshold = clonePointer(c.RPSThreshold)
	c.MaxRejectionProbability = clonePointer(c.MaxRejectionProbability)
	return c
}

func (c *AdmissionControlConfig) validate(name string) error {
	if c == nil {
		return nil
	}
	if err := validateDuration(name+".sampling_window", c.SamplingWindow, false); err != nil {
		return err
	}
	for _, value := range []struct {
		name  string
		value *float64
	}{
		{"sr_threshold", c.SrThreshold},
		{"max_rejection_probability", c.MaxRejectionProbability},
	} {
		if value.value == nil {
			continue
		}
		if math.IsNaN(*value.value) || math.IsInf(*value.value, 0) || *value.value < 0 || *value.value > 100 {
			return fmt.Errorf("%s.%s must be between 0 and 100", name, value.name)
		}
	}
	return nil
}

func (c *AdmissionControlConfig) enabled() bool {
	return c != nil && c.Enabled
}

func (c *AdmissionControlConfig) toEnvoy() *admissioncontrol.AdmissionControl {
	config := defaultAdmissionControlEnvoyConfig()
	config.Enabled = &core.RuntimeFeatureFlag{DefaultValue: wrapperspb.Bool(c.Enabled)}
	if c.SamplingWindow != nil {
		config.SamplingWindow = c.SamplingWindow.protobuf()
	}
	if c.SrThreshold != nil {
		config.SrThreshold = &core.RuntimePercent{DefaultValue: &envoytype.Percent{Value: *c.SrThreshold}}
	}
	if c.RPSThreshold != nil {
		config.RpsThreshold = &core.RuntimeUInt32{DefaultValue: *c.RPSThreshold}
	}
	if c.MaxRejectionProbability != nil {
		config.MaxRejectionProbability = &core.RuntimePercent{DefaultValue: &envoytype.Percent{Value: *c.MaxRejectionProbability}}
	}
	return config
}

func defaultAdmissionControlEnvoyConfig() *admissioncontrol.AdmissionControl {
	return &admissioncontrol.AdmissionControl{
		EvaluationCriteria: &admissioncontrol.AdmissionControl_SuccessCriteria_{SuccessCriteria: &admissioncontrol.AdmissionControl_SuccessCriteria{}},
	}
}
