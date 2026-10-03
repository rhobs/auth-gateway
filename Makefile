.PHONY: test lint e2e update-golden test-runtime
.DEFAULT_GOAL := test

GOLANGCI_LINT_VERSION := v2.14.0

test:
	go test ./...

lint:
	@unformatted=$$(gofmt -l config e2e); \
	if [ -n "$$unformatted" ]; then printf '%s\n' "$$unformatted"; exit 1; fi
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

test-runtime:
	go test -tags=envoyruntime ./config -run TestPinnedImagesValidateGeneratedFiles -count=1

update-golden:
	go test ./config -update

e2e:
	$(MAKE) -C e2e test
