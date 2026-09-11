#!/bin/bash
set -e

echo "Building katwalk..."

# Build the Rust project
cargo build --release

echo ""
echo "Build complete!"
echo "Binary location: target/release/katwalk"
echo ""
echo "To use the tool, you'll need the modulewrapper binary."
echo "Build it from the parent directory:"
echo "  cd .."
echo "  cmake --build build --target modulewrapper"
echo ""
echo "Example usage:"
echo "  ./target/release/katwalk --wrapper ../build/modulewrapper/modulewrapper --regcap"
