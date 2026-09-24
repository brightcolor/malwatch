VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/brightcolor/malwatch/internal/version.Version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64
BINARIES := $(foreach p,$(PLATFORMS),dist/malwatch-$(subst /,-,$(p)))
# Statically linked binaries start on any Linux, whatever its glibc version.
CGO_ENABLED := 0

.PHONY: build test vet fmt clean dist checksums pkg

build:
	CGO_ENABLED=$(CGO_ENABLED) go build -trimpath -ldflags "$(LDFLAGS)" -o dist/malwatch ./cmd/malwatch

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

dist:
	mkdir -p dist
	for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		CGO_ENABLED=$(CGO_ENABLED) GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/malwatch-$$os-$$arch ./cmd/malwatch || exit 1; \
	done
	sh tools/check-static.sh $(BINARIES)

pkg:
	cd ispconfig && sh ./build_package.sh

checksums: dist pkg
	cp ispconfig/malwatch.pkg dist/ 2>/dev/null || true
	cd dist && sha256sum malwatch-* malwatch.pkg > SHA256SUMS

clean:
	rm -rf dist .testbin
