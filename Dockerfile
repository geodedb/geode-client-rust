# Multi-stage Dockerfile for building Rust geode-client
# Builds using standard Ubuntu environment to avoid Nix/BoringSSL issues

FROM rust:1.83-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    pkg-config \
    libssl-dev \
    build-essential \
    git \
    libclang-dev \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy Cargo files first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./

# Create dummy src to cache dependencies
RUN mkdir -p src && \
    echo "fn main() {}" > src/lib.rs && \
    echo "fn main() {}" > build.rs || true

# Build dependencies (this layer will be cached)
RUN cargo build --release || true

# Remove dummy src
RUN rm -rf src build.rs

# Copy actual source code
COPY src ./src
COPY examples ./examples
COPY build.rs ./

# Build the actual library (examples need updating for quiche migration)
RUN cargo build --release

# Create output directory
RUN mkdir -p /output && \
    cp target/release/libgeode_client.rlib /output/ || true && \
    cp target/release/libgeode_client.so /output/ || true && \
    cp target/release/deps/*.rlib /output/ || true

# Final stage - minimal runtime
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security (CWE-250)
RUN groupadd --gid 1000 geode && \
    useradd --uid 1000 --gid 1000 --shell /bin/false --create-home geode

# Copy built artifacts
COPY --from=builder --chown=geode:geode /build/target/release /artifacts

WORKDIR /artifacts

# Switch to non-root user
USER geode

# Default command
CMD ["ls", "-lh"]
