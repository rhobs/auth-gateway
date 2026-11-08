.PHONY: test lint e2e update-golden test-runtime tools
.DEFAULT_GOAL := test

test:
	go test ./...

lint:
	@unformatted=$$(gofmt -l pkg e2e playground); \
	if [ -n "$$unformatted" ]; then printf '%s\n' "$$unformatted"; exit 1; fi
	sh scripts/check-markdown-links.sh
	go tool -modfile=tools/go.mod golangci-lint run

tools:
	go tool ginkgo version
	go tool -modfile=tools/go.mod golangci-lint version
	$(MAKE) -C e2e cmctl kind-tool

test-runtime:
	go test -tags=envoyruntime ./pkg/gateway -run 'TestPinnedImagesValidateGoldenFiles|TestEnvoyReloadsFileBasedResources|TestEnvoyReloadsClientCAForNewConnections|TestEnvoyAdmissionControlIsolatesAPIs|TestEnvoyAPIKeyAttributeLayouts' -count=1

update-golden:
	go test ./pkg/gateway -update

e2e:
	$(MAKE) -C e2e test
