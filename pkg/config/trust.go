package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"

	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	CaCertificateFilename = "ca.crt"
	CaDirectory           = TrustedCADirectory
)

func validateTrustedCA(name string, ca *gatewayapi.TrustedCA, kubernetes bool) error {
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
	if !path.IsAbs(ca.Filename) || path.Clean(ca.Filename) != ca.Filename || ca.Filename == "/" || strings.ContainsAny(ca.Filename, InvalidControlCharacters) {
		return fmt.Errorf("%s.filename must be a clean absolute file path", name)
	}
	return nil
}

func cloneTrustedCA(ca gatewayapi.TrustedCA) gatewayapi.TrustedCA {
	ca.ConfigMap = clonePointer(ca.ConfigMap)
	return ca
}

func IdCAConfigMap(ref gatewayapi.CAConfigMap) string {
	digest := sha256.Sum256([]byte(ref.Name + "\x00" + ref.Key))
	return hex.EncodeToString(digest[:16])
}

// FilePath returns the absolute Envoy path used for this CA ConfigMap entry.
func filePathCAConfigMap(ref gatewayapi.CAConfigMap) string {
	return path.Join(TrustedCADirectory, IdCAConfigMap(ref), CaCertificateFilename)
}

func FilenameTrustedCA(ca gatewayapi.TrustedCA) string {
	if ca.ConfigMap != nil {
		return filePathCAConfigMap(*ca.ConfigMap)
	}
	return ca.Filename
}
