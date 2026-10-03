.PHONY: test e2e update-golden test-runtime

test:
	go test ./...

test-runtime:
	go test -tags=envoyruntime ./config -run TestPinnedImagesValidateGeneratedFiles -count=1

update-golden:
	go run ./cmd/update-golden

e2e:
	$(MAKE) -C e2e test
