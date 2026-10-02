.PHONY: test e2e update-golden

test:
	go test ./...

update-golden:
	go test ./config -update

e2e:
	$(MAKE) -C e2e test
