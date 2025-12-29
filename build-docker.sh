#!/usr/bin/env bash
# Build script for Rust geode-client using Docker
# This avoids Nix/BoringSSL build issues by using a standard Ubuntu container

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMAGE_NAME="geode-rust-builder"
CONTAINER_NAME="geode-rust-build-$$"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed or not in PATH"
    exit 1
fi

# Check if Docker daemon is running
if ! docker info &> /dev/null; then
    log_error "Docker daemon is not running"
    exit 1
fi

log_info "Building Rust client in Docker container..."

# Build the Docker image
log_info "Building Docker image: ${IMAGE_NAME}"
docker build -t "${IMAGE_NAME}" "${SCRIPT_DIR}" || {
    log_error "Failed to build Docker image"
    exit 1
}

log_info "Docker image built successfully"

# Create output directory
OUTPUT_DIR="${SCRIPT_DIR}/target/docker-release"
mkdir -p "${OUTPUT_DIR}"

# Run container and extract artifacts
log_info "Extracting build artifacts from container..."

# Create a temporary container
CONTAINER_ID=$(docker create "${IMAGE_NAME}") || {
    log_error "Failed to create container"
    exit 1
}

# Copy artifacts from container
docker cp "${CONTAINER_ID}:/artifacts/." "${OUTPUT_DIR}/" || {
    log_warn "Failed to copy some artifacts (this may be expected)"
}

# Clean up container
docker rm "${CONTAINER_ID}" > /dev/null

log_info "Build artifacts extracted to: ${OUTPUT_DIR}"
log_info "Listing artifacts:"
ls -lh "${OUTPUT_DIR}" || true

# Check if we got the library files
if ls "${OUTPUT_DIR}"/*.rlib &> /dev/null || ls "${OUTPUT_DIR}"/*.a &> /dev/null; then
    log_info "Build completed successfully!"
    exit 0
else
    log_warn "Build completed but no library artifacts found"
    log_warn "This might be expected for a library crate"
    exit 0
fi
