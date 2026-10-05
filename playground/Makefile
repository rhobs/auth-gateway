.DEFAULT_GOAL := help
.PHONY: help generate start run stop token logs clean

COMPOSE ?= docker compose
ENVOY_IMAGE ?= envoyproxy/envoy:v1.39.1
MOCK_OAUTH2_IMAGE ?= ghcr.io/navikt/mock-oauth2-server:6.0.4
PROMETHEUS_IMAGE ?= prom/prometheus:v3.5.0
HOST_PORT ?= 8080
ENVOY_PORT ?= 8080
OAUTH_HOST_PORT ?= 8443
PROMETHEUS_HOST_PORT ?= 9090

CA_CONFIGMAP := playground-oauth-ca
CA_KEY := ca.crt
CA_MOUNT_ID := $(shell printf '%s\0%s' '$(CA_CONFIGMAP)' '$(CA_KEY)' | shasum -a 256 | cut -c1-32)

export ENVOY_IMAGE MOCK_OAUTH2_IMAGE PROMETHEUS_IMAGE HOST_PORT ENVOY_PORT OAUTH_HOST_PORT PROMETHEUS_HOST_PORT

help:
	@printf '%s\n' \
	  'generate  Generate Envoy files and local authentication resources' \
	  'start     Start Envoy, Mock OAuth, and Prometheus in Docker Compose' \
	  'run       Start the stack and follow its logs' \
	  'token     Request fresh JWTs from both mock OAuth issuers' \
	  'stop      Stop and remove the playground containers' \
	  'clean     Stop the stack and remove generated files' \
	  'Prometheus UI: http://127.0.0.1:$(PROMETHEUS_HOST_PORT)'

generate:
	@set -eu; \
	  command -v yq >/dev/null || { printf '%s\n' 'yq v4 is required to extract generated resources' >&2; exit 1; }; \
	  if [ ! -f credentials.yaml ]; then \
	    cp credentials.example.yaml credentials.yaml; \
	  elif yq -e '((.credentials | length) == 1) and (.credentials[0].key == "playground-demo-key") and (.credentials[0].attributes.user_id == "playground-user") and ((.credentials[0].attributes | keys | length) == 1) and ((.credentials[0] | keys | length) == 2) and ((keys | length) == 1)' credentials.yaml >/dev/null 2>&1; then \
	    cp credentials.example.yaml credentials.yaml; \
	  fi; \
	  chmod 600 credentials.yaml; \
	  umask 077; \
	  mkdir -p generated/api-keys "generated/ca/$(CA_MOUNT_ID)"; \
	  if [ ! -s generated/mock-oauth2.crt ] || [ ! -s generated/mock-oauth2.p12 ] || \
	    ! openssl x509 -in generated/mock-oauth2.crt -noout -ext subjectAltName 2>/dev/null | grep -q 'DNS:mock-oauth2-server'; then \
	    openssl req -x509 -newkey rsa:2048 -nodes \
	      -keyout generated/mock-oauth2.key \
	      -out generated/mock-oauth2.crt \
	      -days 365 \
	      -subj '/CN=auth.localhost' \
	      -addext 'subjectAltName=DNS:auth.localhost,DNS:mock-oauth2-server' \
	      -addext 'basicConstraints=critical,CA:TRUE' \
	      -addext 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign' \
	      -addext 'extendedKeyUsage=serverAuth'; \
	    openssl pkcs12 -export \
	      -in generated/mock-oauth2.crt \
	      -inkey generated/mock-oauth2.key \
	      -out generated/mock-oauth2.p12 \
	      -name mock-oauth2 \
	      -passout pass:playground; \
	    rm generated/mock-oauth2.key; \
	  fi; \
	  cp generated/mock-oauth2.crt "generated/ca/$(CA_MOUNT_ID)/ca.crt"; \
	  chmod 644 generated/mock-oauth2.crt "generated/ca/$(CA_MOUNT_ID)/ca.crt"; \
	  chmod 755 generated generated/ca "generated/ca/$(CA_MOUNT_ID)"; \
	  rm -f generated/envoy.yaml generated/processing.yaml generated/demo.jwt generated/metrics.jwt generated/logs.jwt generated/kubernetes.yaml generated/api-key-secret.yaml generated/api-keys.b64 generated/token-response.json generated/metrics-token-response.json generated/logs-token-response.json generated/api-keys/api-keys.yaml generated/jwks-server.key generated/jwks.json generated/jwt-signing-key.pem generated/jwks-ca.crt; \
	  go run ../examples/generate-kubernetes config.yaml generated/kubernetes.yaml; \
	  files=$$(yq -r 'select(.kind == "ConfigMap" and .data."envoy.yaml" != null) | .data | keys | .[]' generated/kubernetes.yaml); \
	  if [ -z "$$files" ]; then printf '%s\n' 'the generated gateway ConfigMap has no files' >&2; exit 1; fi; \
	  printf '%s\n' "$$files" | while IFS= read -r file; do \
	    CONFIG_FILENAME="$$file" yq -r 'select(.kind == "ConfigMap" and .data."envoy.yaml" != null) | .data[strenv(CONFIG_FILENAME)]' generated/kubernetes.yaml > "generated/$$file"; \
	  done; \
	  go run ../examples/generate-api-key-secret config.yaml credentials.yaml generated/api-key-secret.yaml; \
	  yq -er '.data."api-keys.yaml"' generated/api-key-secret.yaml > generated/api-keys.b64; \
	  openssl base64 -d -A -in generated/api-keys.b64 -out generated/api-keys/api-keys.yaml; \
	  chmod 755 generated/api-keys; \
	  chmod 644 generated/envoy.yaml; \
	  chmod 644 generated/api-keys/api-keys.yaml; \
	  rm -f generated/kubernetes.yaml generated/api-key-secret.yaml generated/api-keys.b64; \
	  printf '%s\n' 'Generated Envoy files and generated/api-keys/api-keys.yaml'

start: generate
	$(COMPOSE) up -d --force-recreate --remove-orphans
	$(MAKE) --no-print-directory token
	@printf '%s\n' \
	  'Envoy: http://unprotected.localhost:$(HOST_PORT)/anything' \
	  'Prometheus: http://127.0.0.1:$(PROMETHEUS_HOST_PORT)' \
	  'Metrics JWT: cat generated/metrics.jwt' \
	  'Logs JWT:    cat generated/logs.jwt'

run: start
	$(COMPOSE) logs --follow

token:
	@set -eu; \
	  if [ ! -s generated/mock-oauth2.crt ]; then printf '%s\n' 'run make generate first' >&2; exit 1; fi; \
	  umask 077; \
	  attempt=0; \
	  until curl --fail --silent --resolve auth.localhost:$(OAUTH_HOST_PORT):127.0.0.1 --cacert generated/mock-oauth2.crt "https://auth.localhost:$(OAUTH_HOST_PORT)/isalive" >/dev/null 2>&1; do \
	    attempt=$$((attempt + 1)); \
	    if [ $$attempt -ge 30 ]; then printf '%s\n' 'mock-oauth2-server did not become ready; check make logs' >&2; exit 1; fi; \
	    sleep 1; \
	  done; \
	  for issuer in metrics logs; do \
	    response_file="generated/$$issuer-token-response.json"; \
	    token_file="generated/$$issuer.jwt"; \
	    curl --fail --silent --show-error \
	      --resolve auth.localhost:$(OAUTH_HOST_PORT):127.0.0.1 \
	      --cacert generated/mock-oauth2.crt \
	      --data-urlencode 'grant_type=client_credentials' \
	      --data-urlencode 'client_id=playground-client' \
	      --data-urlencode 'client_secret=playground-secret' \
	      "https://auth.localhost:$(OAUTH_HOST_PORT)/$$issuer/token" > "$$response_file"; \
	    jq -er '.access_token' "$$response_file" > "$$token_file"; \
	    chmod 600 "$$token_file"; \
	    rm "$$response_file"; \
	  done; \
	  printf '%s\n' 'Wrote generated/metrics.jwt and generated/logs.jwt'

stop:
	$(COMPOSE) down --remove-orphans

logs:
	$(COMPOSE) logs --follow

clean: stop
	rm -rf generated
