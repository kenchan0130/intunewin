PHONY: tidy
tidy:
	@go mod tidy -v

PHONY: install
install:
	@go mod download

PHONY: build
build:
	@go build -o bin/intunewin ./cmd/intunewin

PHONY: format
format:
	@golangci-lint run --fix ./...

PHONY: lint
lint:
	golangci-lint run -v ./...

PHONY: test
test:
	go test -race -v -shuffle on ./...

test/%:
	go vet ./$(@:test/%=%)
	go test -race -v -shuffle on ./$(@:test/%=%)