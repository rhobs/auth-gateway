.PHONY: test e2e

test:
	go test ./...

e2e:
	$(MAKE) -C e2e test
