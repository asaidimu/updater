.PHONY: all test version

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
RELEASE ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "dev")

test:
	go clean -testcache && go test -v ./...

version:
	@echo $(VERSION)

release:
	@echo $(RELEASE)
