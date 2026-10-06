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
	  umask 077; \
	  mkdir -p generated; \
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
	  chmod 644 generated/mock-oauth2.crt; \
	  chmod 755 generated; \
	  umask 022; \
	  go test ../config -run '^TestPlaygroundBootstrap$$' -count=1 -update; \
	  rm -f generated/envoy.yaml generated/processing/processing.yaml generated/api-keys/api-keys.yaml generated/metrics.jwt generated/logs.jwt generated/metrics-token-response.json generated/logs-token-response.json; \
	  cp envoy.yaml.golden generated/envoy.yaml; \
	  chmod 644 generated/envoy.yaml; \
	  printf '%s\n' 'Generated Envoy bootstrap and local OAuth certificate'

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
