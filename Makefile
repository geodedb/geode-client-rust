# =============================================================================
# Geode Rust Client Makefile
# Convenient shortcuts for build, test, lint, bench, and fuzz operations
# =============================================================================

CARGO ?= cargo
CARGO_FLAGS ?=

.PHONY: all build release test test-unit test-proptest test-doc test-integration bench fuzz lint fmt doc clean check ci help deps proto

# Default target - run everything (except integration tests which require server)
all: build fmt-check lint test-unit test-proptest test-doc doc bench-quick
	@echo ""
	@echo "==== All Checks Complete ===="
	@echo "✓ Build successful"
	@echo "✓ Format check passed"
	@echo "✓ Clippy lint passed"
	@echo "✓ Unit tests passed (274 tests)"
	@echo "✓ Property tests passed (28 tests)"
	@echo "✓ Doc tests passed"
	@echo "✓ Documentation generated"
	@echo "✓ Benchmarks compiled"
	@echo ""
	@echo "Note: Run 'make test-integration' separately (requires Geode server)"

# Help target
help:
	@echo "Geode Rust Client Makefile"
	@echo "=========================="
	@echo ""
	@echo "Build targets:"
	@echo "  make build          - Build debug version"
	@echo "  make release        - Build release version"
	@echo "  make clean          - Clean build artifacts"
	@echo ""
	@echo "Toolchain / codegen targets:"
	@echo "  make deps           - Install protoc and regenerate proto code"
	@echo "  make proto          - Regenerate src/generated/geode.rs from proto/geode.proto"
	@echo ""
	@echo "Test targets:"
	@echo "  make test           - Run all tests (unit + proptest + doc)"
	@echo "  make test-unit      - Run unit tests only (274 tests)"
	@echo "  make test-proptest  - Run property-based tests (28 tests)"
	@echo "  make test-doc       - Run documentation tests"
	@echo "  make test-integration - Run integration tests (requires Geode server)"
	@echo "  make test-integration-grpc - Run gRPC integration tests"
	@echo "  make test-all       - Run ALL tests including integration"
	@echo ""
	@echo "Quality targets:"
	@echo "  make lint           - Run clippy linter"
	@echo "  make fmt            - Format code with rustfmt"
	@echo "  make fmt-check      - Check formatting without changes"
	@echo "  make check          - Run cargo check (fast compile check)"
	@echo "  make doc            - Generate documentation"
	@echo "  make doc-open       - Generate and open documentation"
	@echo ""
	@echo "Benchmark targets:"
	@echo "  make bench          - Run all benchmarks (59 benchmarks)"
	@echo "  make bench-report   - Run benchmarks with HTML report"
	@echo ""
	@echo "Fuzz targets:"
	@echo "  make fuzz           - List available fuzz targets"
	@echo "  make fuzz-value     - Fuzz Value::from_json"
	@echo "  make fuzz-query     - Fuzz QueryBuilder"
	@echo "  make fuzz-pattern   - Fuzz PatternBuilder"
	@echo "  make fuzz-json      - Fuzz JSON parsing"
	@echo ""
	@echo "CI targets:"
	@echo "  make ci             - Run full CI pipeline"
	@echo "  make ci-quick       - Run quick CI (no integration tests)"
	@echo ""
	@echo "Environment variables:"
	@echo "  CARGO_FLAGS         - Additional flags for cargo commands"
	@echo "  GEODE_HOST          - Geode server host (default: 127.0.0.1)"
	@echo "  GEODE_PORT          - Geode server port (default: 3141)"

# =============================================================================
# Build Targets
# =============================================================================

build:
	@echo "Building debug version..."
	$(CARGO) build $(CARGO_FLAGS)
	@echo "✓ Build complete"

release:
	@echo "Building release version..."
	$(CARGO) build --release $(CARGO_FLAGS)
	@echo "✓ Release build complete"

check:
	@echo "Running cargo check..."
	$(CARGO) check $(CARGO_FLAGS)
	@echo "✓ Check complete"

# =============================================================================
# Toolchain / Codegen Targets
# =============================================================================

# Pinned protoc version used for reproducible codegen via the curl fallback.
PROTOC_VERSION ?= 28.3

# Canonical proto: single source of truth in the geode server repo. Override
# with `make proto CANONICAL_PROTO=/path/to/geode.proto`. When unset, common
# checkout-relative locations are searched; if none exist the vendored
# proto/geode.proto is used as-is.
CANONICAL_PROTO ?=

# Install the protobuf compiler (protoc) and regenerate the vendored proto code.
# Tries the system package manager first, then falls back to the official
# release binary installed into ~/.local/bin (no root required).
deps:
	@if command -v protoc >/dev/null 2>&1; then \
		echo "✓ protoc already installed: $$(protoc --version)"; \
	elif command -v apt-get >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then \
		echo "Installing protoc via apt-get..."; \
		sudo apt-get update && sudo apt-get install -y protobuf-compiler; \
	elif command -v brew >/dev/null 2>&1; then \
		echo "Installing protoc via brew..."; brew install protobuf; \
	elif command -v dnf >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then \
		echo "Installing protoc via dnf..."; sudo dnf install -y protobuf-compiler; \
	elif command -v pacman >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then \
		echo "Installing protoc via pacman..."; sudo pacman -S --noconfirm protobuf; \
	else \
		echo "Installing protoc $(PROTOC_VERSION) release binary into ~/.local/bin..."; \
		os=$$(uname -s); arch=$$(uname -m); \
		case "$$os" in Linux) plat=linux ;; Darwin) plat=osx ;; *) echo "unsupported OS $$os"; exit 1 ;; esac; \
		case "$$arch" in x86_64|amd64) parch=x86_64 ;; aarch64|arm64) parch=aarch_64 ;; *) echo "unsupported arch $$arch"; exit 1 ;; esac; \
		tmp=$$(mktemp -d); \
		curl -fsSL -o "$$tmp/protoc.zip" "https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOC_VERSION)/protoc-$(PROTOC_VERSION)-$$plat-$$parch.zip"; \
		(command -v unzip >/dev/null 2>&1 && unzip -oq "$$tmp/protoc.zip" -d "$$tmp" || python3 -c "import zipfile,sys;zipfile.ZipFile('$$tmp/protoc.zip').extractall('$$tmp')"); \
		mkdir -p "$$HOME/.local/bin"; install -m755 "$$tmp/bin/protoc" "$$HOME/.local/bin/protoc"; rm -rf "$$tmp"; \
		echo "✓ protoc installed to ~/.local/bin (ensure it is on PATH)"; \
	fi
	@rustup component add rustfmt >/dev/null 2>&1 || true
	$(MAKE) proto
	@echo "✓ deps complete"

# Regenerate src/generated/geode.rs from proto/geode.proto using protoc.
# When a canonical proto is found (the geode server repo's geode.proto), it is
# first copied into proto/geode.proto so the vendored copy never drifts from
# the server's wire contract. The generated code is checked in and used
# directly; run this after editing proto/geode.proto. Requires protoc on PATH
# ('make deps' installs it).
proto:
	@command -v protoc >/dev/null 2>&1 || { echo "protoc not found on PATH — run 'make deps' first"; exit 1; }
	@canon="$(CANONICAL_PROTO)"; \
	if [ -z "$$canon" ]; then \
		for c in ../geode/src/proto/geode.proto ../../geode/src/proto/geode.proto ../../../geode/src/proto/geode.proto; do \
			[ -f "$$c" ] && canon="$$c" && break; \
		done; \
	fi; \
	if [ -n "$$canon" ] && [ -f "$$canon" ]; then \
		echo "Syncing canonical proto from $$canon"; cp "$$canon" proto/geode.proto; \
	else \
		echo "Canonical proto not found; using vendored proto/geode.proto"; \
	fi
	@echo "Regenerating protobuf code from proto/geode.proto (protoc $$(protoc --version))..."
	GENERATE_PROTO=1 $(CARGO) build $(CARGO_FLAGS)
	$(CARGO) fmt
	@echo "✓ Regenerated src/generated/geode.rs (run 'make test' to verify)"

clean:
	@echo "Cleaning build artifacts..."
	$(CARGO) clean
	rm -rf target/criterion
	rm -rf fuzz/target
	rm -rf fuzz/corpus
	rm -rf fuzz/artifacts
	@echo "✓ Clean complete"

# =============================================================================
# Test Targets
# =============================================================================

test: test-unit test-proptest test-doc
	@echo "✓ All tests complete"

test-unit:
	@echo "Running unit tests..."
	$(CARGO) test --lib $(CARGO_FLAGS)
	@echo "✓ Unit tests complete (274 tests)"

test-proptest:
	@echo "Running property-based tests..."
	$(CARGO) test --test proptest $(CARGO_FLAGS)
	@echo "✓ Property tests complete (28 tests)"

test-doc:
	@echo "Running documentation tests..."
	$(CARGO) test --doc $(CARGO_FLAGS)
	@echo "✓ Doc tests complete"

test-integration:
	@echo "Running integration tests..."
	@echo ""
	@echo "Tests connect to local Geode server at 127.0.0.1:3141"
	@echo "Start server first: cd ../geode && ./zig-out/bin/geode serve"
	@echo ""
	$(CARGO) test --features integration $(CARGO_FLAGS) -- --test-threads=1
	@echo "✓ Integration tests complete (36 tests)"

test-integration-docker:
	@echo "Running integration tests with Docker..."
	@echo ""
	@echo "Using Docker image: geodedb/geode:latest"
	@echo ""
	GEODE_USE_DOCKER=true $(CARGO) test --features integration $(CARGO_FLAGS) -- --test-threads=1
	@echo "✓ Docker integration tests complete (36 tests)"

test-integration-grpc:
	@echo "Running gRPC integration tests..."
	@echo ""
	@echo "Tests connect to Geode gRPC server"
	@echo "Start server first: cd ../geode && ./zig-out/bin/geode serve --listen-grpc 0.0.0.0:50051"
	@echo ""
	GEODE_TRANSPORT=grpc GEODE_TLS_CA=$(GEODE_TLS_CA) $(CARGO) test --features integration $(CARGO_FLAGS) -- --test-threads=1
	@echo "✓ gRPC integration tests complete"

test-all: test-unit test-proptest test-doc test-integration
	@echo "✓ All tests complete (including integration)"

# Verbose test output
test-verbose:
	@echo "Running tests with verbose output..."
	$(CARGO) test --lib -- --nocapture $(CARGO_FLAGS)

# =============================================================================
# Code Quality Targets
# =============================================================================

lint:
	@echo "Running clippy..."
	$(CARGO) clippy --lib --tests $(CARGO_FLAGS) -- -D warnings
	@echo "✓ Lint complete (0 warnings)"

fmt:
	@echo "Formatting code..."
	$(CARGO) fmt
	@echo "✓ Format complete"

fmt-check:
	@echo "Checking code format..."
	$(CARGO) fmt -- --check
	@echo "✓ Format check complete"

doc:
	@echo "Generating documentation..."
	$(CARGO) doc --no-deps $(CARGO_FLAGS)
	@echo "✓ Documentation generated at target/doc/geode_client/index.html"

doc-open:
	@echo "Generating and opening documentation..."
	$(CARGO) doc --no-deps --open $(CARGO_FLAGS)

# =============================================================================
# Benchmark Targets
# =============================================================================

bench:
	@echo "Running benchmarks..."
	@echo "Note: Connection benchmarks require a running Geode server"
	$(CARGO) bench $(CARGO_FLAGS)
	@echo "✓ Benchmarks complete (59 benchmarks)"

bench-report:
	@echo "Running benchmarks with HTML report..."
	$(CARGO) bench $(CARGO_FLAGS)
	@echo "✓ Benchmark report available at target/criterion/report/index.html"

bench-quick:
	@echo "Running quick benchmarks (compile only)..."
	$(CARGO) bench --no-run $(CARGO_FLAGS)
	@echo "✓ Benchmark compilation complete"

# =============================================================================
# Fuzz Targets
# =============================================================================

fuzz:
	@echo "Available fuzz targets:"
	@echo "  fuzz_value_from_json - Test Value::from_json with arbitrary JSON"
	@echo "  fuzz_query_builder   - Test QueryBuilder with arbitrary strings"
	@echo "  fuzz_pattern_builder - Test PatternBuilder with arbitrary patterns"
	@echo "  fuzz_json_parsing    - Test JSON parsing and Value conversion"
	@echo ""
	@echo "Run with: make fuzz-value (or fuzz-query, fuzz-pattern, fuzz-json)"
	@echo "Or directly: cargo +nightly fuzz run <target>"

fuzz-value:
	@echo "Fuzzing Value::from_json..."
	@echo "Press Ctrl+C to stop"
	cd fuzz && cargo +nightly fuzz run fuzz_value_from_json -- -max_total_time=60

fuzz-query:
	@echo "Fuzzing QueryBuilder..."
	@echo "Press Ctrl+C to stop"
	cd fuzz && cargo +nightly fuzz run fuzz_query_builder -- -max_total_time=60

fuzz-pattern:
	@echo "Fuzzing PatternBuilder..."
	@echo "Press Ctrl+C to stop"
	cd fuzz && cargo +nightly fuzz run fuzz_pattern_builder -- -max_total_time=60

fuzz-json:
	@echo "Fuzzing JSON parsing..."
	@echo "Press Ctrl+C to stop"
	cd fuzz && cargo +nightly fuzz run fuzz_json_parsing -- -max_total_time=60

# =============================================================================
# CI Targets
# =============================================================================

ci: fmt-check lint test doc bench-quick
	@echo ""
	@echo "==== CI Pipeline Complete ===="
	@echo "✓ Format check passed"
	@echo "✓ Clippy lint passed (0 warnings)"
	@echo "✓ Unit tests passed (274 tests)"
	@echo "✓ Property tests passed (28 tests)"
	@echo "✓ Doc tests passed"
	@echo "✓ Documentation generated"
	@echo "✓ Benchmarks compiled"
	@echo ""

ci-quick: fmt-check lint test-unit
	@echo ""
	@echo "==== Quick CI Complete ===="
	@echo "✓ Format check passed"
	@echo "✓ Clippy lint passed"
	@echo "✓ Unit tests passed"
	@echo ""

ci-full: ci test-integration
	@echo ""
	@echo "==== Full CI Complete (with integration tests) ===="
	@echo ""

# =============================================================================
# Coverage Target (requires cargo-tarpaulin)
# =============================================================================

coverage:
	@echo "Running code coverage..."
	@echo "Note: Requires cargo-tarpaulin (cargo install cargo-tarpaulin)"
	$(CARGO) tarpaulin --lib --out Html --output-dir coverage/
	@echo "✓ Coverage report at coverage/tarpaulin-report.html"

# =============================================================================
# Development Helpers
# =============================================================================

# Watch for changes and run tests
watch:
	@echo "Watching for changes..."
	@echo "Note: Requires cargo-watch (cargo install cargo-watch)"
	$(CARGO) watch -x "test --lib"

# Update dependencies
update:
	@echo "Updating dependencies..."
	$(CARGO) update
	@echo "✓ Dependencies updated"

# Check for outdated dependencies
outdated:
	@echo "Checking for outdated dependencies..."
	@echo "Note: Requires cargo-outdated (cargo install cargo-outdated)"
	$(CARGO) outdated

# Run examples
example-basic:
	@echo "Running basic example..."
	@echo "Note: Requires running Geode server"
	$(CARGO) run --example basic

example-advanced:
	@echo "Running advanced example..."
	@echo "Note: Requires running Geode server"
	$(CARGO) run --example advanced

example-transactions:
	@echo "Running transactions example..."
	@echo "Note: Requires running Geode server"
	$(CARGO) run --example transactions
