VERSION ?= dev
LDFLAGS := -s -w -X github.com/whywaita/thatchbox/internal/cli.Version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

.PHONY: test build check cover dist
test:
	go test -race ./...
build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o thatchbox ./cmd/thatchbox
check:
	test -z "$$(gofmt -l cmd internal tests)"
	go vet ./...
	go test -race ./...
# Tests live in tests/, so coverage is measured across every package.
cover:
	go test -coverpkg=./... -coverprofile=coverage.out ./...
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
