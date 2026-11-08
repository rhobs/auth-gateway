package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	caCertificateFilename = "ca.crt"
	caDirectory           = TrustedCADirectory
)

// TrustedCA selects a replacement trust bundle. Omission uses the system bundle.
type TrustedCA struct {
	Filename  string       `yaml:"filename,omitempty"`
	ConfigMap *CAConfigMap `yaml:"config_map,omitempty"`
}

// CAConfigMap references one key of an existing ConfigMap in the gateway namespace.
type CAConfigMap struct {
	Name string `yaml:"name"`
	Key  string `yaml:"key"`
}

func validateTrustedCA(name string, ca *TrustedCA, kubernetes bool) error {
	if ca == nil {
		return nil
	}
	if (ca.Filename != "") == (ca.ConfigMap != nil) {
		return fmt.Errorf("%s must select exactly one of filename or config_map", name)
	}
	if ca.ConfigMap != nil {
		if !kubernetes {
			return fmt.Errorf("%s.config_map requires kubernetes settings to provision the CA mount", name)
		}
		if len(validation.IsDNS1123Subdomain(ca.ConfigMap.Name)) != 0 {
			return fmt.Errorf("%s.config_map.name must be a valid ConfigMap name", name)
		}
		if len(validation.IsConfigMapKey(ca.ConfigMap.Key)) != 0 {
			return fmt.Errorf("%s.config_map.key must be a valid ConfigMap key", name)
		}
		return nil
	}
	if !path.IsAbs(ca.Filename) || path.Clean(ca.Filename) != ca.Filename || ca.Filename == "/" || strings.ContainsAny(ca.Filename, invalidControlCharacters) {
		return fmt.Errorf("%s.filename must be a clean absolute file path", name)
	}
	return nil
}

func (ca TrustedCA) clone() TrustedCA {
	ca.ConfigMap = clonePointer(ca.ConfigMap)
	return ca
}

func (ref CAConfigMap) id() string {
	digest := sha256.Sum256([]byte(ref.Name + "\x00" + ref.Key))
	return hex.EncodeToString(digest[:16])
}

// FilePath returns the absolute Envoy path used for this CA ConfigMap entry.
func (ref CAConfigMap) FilePath() string {
	return path.Join(TrustedCADirectory, ref.id(), caCertificateFilename)
}

func (ca TrustedCA) filename() string {
	if ca.ConfigMap != nil {
		return ca.ConfigMap.FilePath()
	}
	return ca.Filename
}
