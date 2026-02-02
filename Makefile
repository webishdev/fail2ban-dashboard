.PHONY: build test clean help

# Variables
VERSION ?= development
GIT_HASH := $(shell git rev-parse --short=11 HEAD)
BIN_DIR := bin
BINARY_NAME := fail2ban-dashboard
MAIN_PATH := ./cmd/fail2ban-dashboard

# Default target
all: test build

# Build the application
build:
	@echo "Building $(BINARY_NAME) version $(VERSION) ($(GIT_HASH))"
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 go build \
		-ldflags="-s -w -X 'main.Version=$(VERSION)' -X 'main.GitHash=$(GIT_HASH)'" \
		-o $(BIN_DIR)/$(BINARY_NAME) $(MAIN_PATH)

# Run tests
test:
	@echo "Running tests"
	go test ./...

test-ci:
	@echo "Running tests for CI/CD"
	go test ./... -json > testresults.json

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts"
	@rm -rf $(BIN_DIR)

# Show help
help:
	@echo "Available targets:"
	@echo "  all     - Run tests and build the application (default)"
	@echo "  test    - Run tests"
	@echo "  build   - Build the application"
	@echo "  clean   - Remove build artifacts"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION - Version to embed in binary (default: development)"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make build VERSION=v1.0.0"
	@echo "  make clean"