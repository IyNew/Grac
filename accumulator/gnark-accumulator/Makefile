# Makefile for accumulator/gnark-accumulator

.PHONY: all setup bench test clean deps rust-bridge build-run

# Default target
all: deps setup bench

# Install dependencies
deps:
	@echo "Installing Go dependencies..."
	cd cmd/bench && go mod tidy
	cd ..

# Build and run the Rust bridge
rust-bridge:
	@echo "Building and starting Rust bridge server..."
	cd ../cpsnarks-set-bridge
	cargo build --release
	cargo run --release &
	sleep 2
	cd ../gnark-accumulator

# Build the benchmark binary
build:
	@echo "Building benchmark binary..."
	cd cmd/bench && go build -o ../../bench .
	cd ../..

# Run the benchmark
bench: build
	@echo "Running accumulator non-membership verification benchmark..."
	./bench -prove-iterations 50 -verify-iterations 200 -verbose

# Run benchmark with custom parameters
bench-custom: build
	@echo "Running benchmark with custom parameters..."
	./bench -prove-iterations $(PROVE_ITERATIONS) -verify-iterations $(VERIFY_ITERATIONS) -security-level $(SECURITY_LEVEL) -verbose

# Run full benchmark setup and execution
run-all: rust-bridge bench
	@echo "Full benchmark completed"

# Run benchmark with comparison to Rust
bench-compare: build
	@echo "Running benchmark with Rust comparison..."
	./bench -prove-iterations 50 -verify-iterations 200 -compare-rust -output benchmark_results.json -verbose

# Run a quick test
test: build
	@echo "Running quick test..."
	./bench -prove-iterations 5 -verify-iterations 10 -verbose

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f bench
	rm -f benchmark_results.json
	cd ../cpsnarks-set-bridge && cargo clean
	cd ../gnark-accumulator

# Install Rust dependencies
rust-deps:
	@echo "Installing Rust dependencies..."
	cd ../cpsnarks-set-bridge && cargo build --release
	cd ../gnark-accumulator

# Run tests
run-tests: deps
	@echo "Running tests..."
	cd cmd/bench && go test -v ../..
	cd ../..

# Development setup for first-time users
setup-deps: rust-deps deps
	@echo "Development dependencies installed"

# Help target
help:
	@echo "Available targets:"
	@echo "  all            - Run complete setup and benchmark"
	@echo "  deps           - Install Go dependencies"
	@echo "  rust-deps      - Install Rust dependencies"
	@echo "  setup-deps     - Install all dependencies"
	@echo "  rust-bridge    - Build and start Rust bridge server"
	@echo "  build          - Build benchmark binary"
	@echo "  bench          - Run default benchmark"
	@echo "  bench-custom    - Run benchmark with custom parameters"
	@echo "  bench-compare  - Run benchmark with Rust comparison"
	@echo "  run-all        - Run Rust bridge and benchmark"
	@echo "  test           - Run quick test"
	@echo "  run-tests      - Run Go tests"
	@echo "  clean          - Clean build artifacts"
	@echo "  help           - Show this help message"
	@echo ""
	@echo "Example usage:"
	@echo "  make setup-deps"
	@echo "  make rust-bridge"
	@echo "  make bench-compare"
	@echo ""
	@echo "Custom benchmark:"
	@echo "  PROVE_ITERATIONS=100 VERIFY_ITERATIONS=1000 SECURITY_LEVEL=128 make bench-custom"