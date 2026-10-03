.PHONY: test e2e update-golden

test:
	go test ./...

update-golden:
	go run ./cmd/update-golden

e2e:
	$(MAKE) -C e2e test
