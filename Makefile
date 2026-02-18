MODULE   := github.com/ethanolivertroy/okta-inspector
BINARY   := okta-inspector
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE     := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS  := -s -w \
	-X '$(MODULE)/internal/version.Version=$(VERSION)' \
	-X '$(MODULE)/internal/version.Commit=$(COMMIT)' \
	-X '$(MODULE)/internal/version.Date=$(DATE)'

.PHONY: build run test lint clean tidy

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

run: build
	./$(BINARY)

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY)
	rm -rf dist/

tidy:
	go mod tidy

snapshot:
	goreleaser release --snapshot --clean
