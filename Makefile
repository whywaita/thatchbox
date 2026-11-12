VERSION ?= dev
LDFLAGS := -s -w -X github.com/whywaita/thatchbox/internal/cli.Version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

.PHONY: test build check cover dist
test:
	go test -race ./...
build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o thatchbox ./cmd/thatchbox
check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...
# Packages are also exercised by their neighbours' tests (collect drives
# sshdial, telnet and shell), so coverage counts every package except the
# test fakes.
COVERPKG = $(shell go list ./... | grep -v /internal/testutil | paste -sd, -)
cover:
	go test -coverpkg=$(COVERPKG) -coverprofile=coverage.out ./...
# Release archives and their checksums in dist/.
dist:
	rm -rf dist && mkdir -p dist
	set -e; for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; name=thatchbox_$(VERSION)_$${os}_$${arch}; \
		mkdir -p dist/$$name; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$$name/thatchbox ./cmd/thatchbox; \
		cp LICENSE README.md dist/$$name/; \
		tar -C dist -czf dist/$$name.tar.gz $$name; \
		rm -rf dist/$$name; \
	done
	cd dist && sha256sum *.tar.gz > checksums.txt
