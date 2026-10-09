.PHONY: test lint e2e update-golden test-runtime
.DEFAULT_GOAL := test

test:
	go test ./...

lint:
	@unformatted=$$(gofmt -l config e2e playground); \
	if [ -n "$$unformatted" ]; then printf '%s\n' "$$unformatted"; exit 1; fi
	sh scripts/check-markdown-links.sh
	go tool golangci-lint run

test-runtime:
	go test -tags=envoyruntime ./config -run TestPinnedImagesValidateGeneratedFiles -count=1

update-golden:
	go test ./config -update

e2e:
	$(MAKE) -C e2e test
