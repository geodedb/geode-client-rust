#!/bin/bash
# Install protoc for Rust (prost uses build.rs for code generation)
set -e

PROTOC_VERSION="28.3"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

if [ "$ARCH" = "x86_64" ]; then
    ARCH="x86_64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    ARCH="aarch_64"
fi

if [ "$OS" = "darwin" ]; then
    OS="osx"
fi

# Download protoc
PROTOC_ZIP="protoc-${PROTOC_VERSION}-${OS}-${ARCH}.zip"
PROTOC_URL="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/${PROTOC_ZIP}"

echo "Downloading protoc from ${PROTOC_URL}..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TOOLS_DIR="${PROJECT_DIR}/.tools"

mkdir -p "${TOOLS_DIR}"
cd "${TOOLS_DIR}"

if [ ! -f "protoc/bin/protoc" ]; then
    curl -LO "${PROTOC_URL}"
    unzip -o "${PROTOC_ZIP}" -d protoc
    rm -f "${PROTOC_ZIP}"
fi

export PATH="${TOOLS_DIR}/protoc/bin:$PATH"

# Create proto directory
mkdir -p "${PROJECT_DIR}/proto"

# Copy proto file if not exists
if [ ! -f "${PROJECT_DIR}/proto/geode.proto" ]; then
    echo "Proto file not found. Please copy geode.proto to proto/ directory."
    exit 1
fi

echo "Protoc installed at ${TOOLS_DIR}/protoc/bin/protoc"
echo ""
echo "To build with protoc, set PROTOC environment variable:"
echo "  export PROTOC=${TOOLS_DIR}/protoc/bin/protoc"
echo ""
echo "Then run: cargo build"
echo ""
echo "Note: prost-build in build.rs will generate Rust code automatically."
