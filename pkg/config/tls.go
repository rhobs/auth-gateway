package config

import (
	"strconv"
)

const (
	GoogleHTTP11ALPN       = "http/1.1"
	SystemCABundle         = "/etc/ssl/certs/ca-certificates.crt"
	TlsTransportSocketName = "envoy.transport_sockets.tls"
)

func ServerTLSSecretName(index int) string {
	return "gateway_server_" + strconv.Itoa(index)
}

func ServerTLSResourceFilename(index int) string {
	return "server-certificate-" + strconv.Itoa(index) + ".yaml"
}

func ClientCASecretName(index int) string {
	return "gateway_client_ca_" + strconv.Itoa(index)
}

func ClientCAResourceFilename(index int) string {
	return "client-ca-" + strconv.Itoa(index) + ".yaml"
}
