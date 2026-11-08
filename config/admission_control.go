package config

import (
	"fmt"
	"math"
)

// AdmissionControlConfig optionally sheds requests based on one API's success rate.
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

func (c AdmissionControlConfig) validate(name string) error {
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
