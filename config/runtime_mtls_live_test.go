//go:build envoyruntime

package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	clienttls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	runtimeMTLSCAPath = EnvoyConfigDirectory + "/runtime-client-ca.crt"
	runtimeMTLSURI    = "spiffe://clients.example.test/client-a"
)

func TestEnvoyReloadsClientCAForNewConnections(t *testing.T) {
	config := runtimeMTLSConfig(t)
	files, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(files.ClientCAResources) != 1 || len(files.ServerCertificateResources) != 1 {
		t.Fatalf("generated %d client CA and %d server certificate resources, want one each", len(files.ClientCAResources), len(files.ServerCertificateResources))
	}
	configDir := runtimeDirectory(t)
	for _, file := range files.All() {
		runtimeLiveWriteGeneratedFile(t, configDir, file)
	}
	server := runtimeLiveCertificates(t)[0]
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(server.certificate)
	runtimeLiveWriteGeneratedFile(t, configDir, GeneratedFile{Path: config.Servers[0].TLSConfig.Certificate, Contents: server.certificatePEM})
	runtimeLiveWriteGeneratedFile(t, configDir, GeneratedFile{Path: config.Servers[0].TLSConfig.PrivateKey, Contents: server.privateKeyPEM})
	caA, clientA := runtimeMTLSClient(t, 1)
	caB, clientB := runtimeMTLSClient(t, 2)
	runtimeLiveWriteGeneratedFile(t, configDir, GeneratedFile{Path: runtimeMTLSCAPath, Contents: caA})

	harness := runtimeLiveStart(t, configDir, serverRoots)
	requestWith := func(certificate clienttls.Certificate) runtimeLiveResponse {
		client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &clienttls.Config{
			RootCAs: serverRoots, ServerName: runtimeLiveTLSHost, Certificates: []clienttls.Certificate{certificate}, MinVersion: clienttls.VersionTLS12,
		}}, Timeout: 4 * time.Second}
		withClient := *harness
		withClient.tlsClient = client
		return withClient.request(true, runtimeLiveTLSHost, "", http.MethodPost, "/ingest", runtimeLiveBody)
	}
	runtimeLiveAwait(t, harness, "initial client CA", time.Time{}, func() (bool, string) {
		response := requestWith(clientA)
		return runtimeLiveEchoMatches(response, http.StatusOK, runtimeMTLSURI, http.MethodPost, "/anything", runtimeLiveBody), response.describe()
	})
	if rejected := requestWith(clientB); rejected.err == nil {
		t.Fatalf("client B was accepted before CA rotation: %s", rejected.describe())
	}
	updatedAt := runtimeLiveAtomicReplace(t, harness, runtimeMTLSCAPath, caB)
	runtimeLiveAwait(t, harness, "rotated client CA", updatedAt, func() (bool, string) {
		response := requestWith(clientB)
		return runtimeLiveEchoMatches(response, http.StatusOK, runtimeMTLSURI, http.MethodPost, "/anything", runtimeLiveBody), response.describe()
	})
	if rejected := requestWith(clientA); rejected.err == nil {
		t.Fatalf("client A was accepted after CA rotation: %s", rejected.describe())
	}
}

func runtimeMTLSConfig(t *testing.T) Config {
	t.Helper()
	input := `version: 1
authenticators:
  - name: client-cert
    mtls:
      trusted_ca: {filename: /etc/auth-gateway/runtime-client-ca.crt}
    attributes:
      tenant_id: {uri_san: true}
authorization_policies:
  - name: writers
    grants:
      - authenticator: client-cert
        apis: [ingest]
        attributes:
          tenant_id: [spiffe://clients.example.test/client-a]
apis:
  - name: ingest
    upstream: {address: httpbin, port: 8080}
    routes:
      - methods: [POST]
        path: {exact: /ingest}
        rewrite: {path: /anything}
        processing:
          request_headers:
            - {name: X-Scope-OrgID, from_attribute: tenant_id}
servers:
  - hostname: tls.runtime.test
    tls_config:
      certificate: /etc/auth-gateway/runtime-server.crt
      private_key: /etc/auth-gateway/runtime-server.key
    authentication: {any_of: [client-cert]}
    authorization: {any_of: [writers]}
    apis: [ingest]
`
	c, err := Load(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func runtimeMTLSClient(t *testing.T, serial int64) ([]byte, clienttls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(serial * 100), Subject: pkix.Name{CommonName: "runtime client CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(runtimeMTLSURI)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(serial*100 + 1), Subject: pkix.Name{CommonName: "runtime client"},
		DNSNames: []string{"client-a.example.test"}, URIs: []*url.URL{uri}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, ca, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	clientPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	certificate, err := clienttls.X509KeyPair(clientPEM, privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	return caPEM, certificate
}
