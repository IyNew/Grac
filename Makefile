# Gr2AC zkSNARK Implementation Makefile

.PHONY: help build test demo clean deps bench

# Default target
help:
	@echo "Gr2AC zkSNARK Implementation"
	@echo "Available targets:"
	@echo "  help     - Show this help message"
	@echo "  deps     - Install dependencies"
	@echo "  build    - Build the project"
	@echo "  test     - Run tests"
	@echo "  bench    - Run benchmarks"
	@echo "  demo     - Run the demo application"
	@echo "  clean    - Clean build artifacts"

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Build the project
build: deps
	@echo "Building project..."
	go build ./...

# Run tests
test: build
	@echo "Running tests..."
	cd tests && go test -v

# Run benchmarks
bench: build
	@echo "Running benchmarks..."
	cd tests && go test -bench=. -benchmem

# Run demo
demo: build
	@echo "Running demo..."
	cd examples && go run demo.go

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	go clean -cache
	rm -f examples/demo
	rm -f tests/*.test

# Install development dependencies
dev-deps: deps
	@echo "Installing development dependencies..."
	go install github.com/stretchr/testify/assert@latest
	go install github.com/stretchr/testify/require@latest

# Full test suite
full-test: build test bench
	@echo "Full test suite completed"

# Development setup
setup: dev-deps
	@echo "Development setup completed"