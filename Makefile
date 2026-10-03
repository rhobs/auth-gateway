.PHONY: test e2e update-golden test-runtime
.DEFAULT_GOAL := test

test:
	go test ./...

test-runtime:
	go test -tags=envoyruntime ./config -run TestPinnedImagesValidateGeneratedFiles -count=1

update-golden:
	go test ./config -update

e2e:
	$(MAKE) -C e2e test
