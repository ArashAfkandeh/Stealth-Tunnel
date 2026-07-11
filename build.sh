#!/bin/bash
# GhostRPC Auto Build Script

set -e

echo "==========================================="
echo "   GhostRPC Auto Build Script              "
echo "==========================================="

# 1. Update and install basic dependencies
echo "[*] Checking and installing basic build dependencies..."
if command -v apt-get &> /dev/null; then
    sudo apt-get update -y
    sudo apt-get install -y curl build-essential pkg-config libssl-dev
elif command -v yum &> /dev/null; then
    sudo yum update -y
    sudo yum groupinstall -y "Development Tools"
    sudo yum install -y curl openssl-devel
elif command -v dnf &> /dev/null; then
    sudo dnf update -y
    sudo dnf groupinstall -y "Development Tools"
    sudo dnf install -y curl openssl-devel
elif command -v pacman &> /dev/null; then
    sudo pacman -Sy --noconfirm base-devel curl openssl
else
    echo "[!] Unsupported package manager. Please install build essentials and OpenSSL manually."
fi

# 2. Check and install Rust/Cargo
if ! command -v cargo &> /dev/null; then
    echo "[*] Rust (Cargo) is not installed. Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    
    # Source the environment variables for the current session
    export PATH="$HOME/.cargo/bin:$PATH"
    echo "[*] Rust has been successfully installed."
else
    echo "[*] Rust is already installed: $(cargo --version)"
fi

# 3. Build the project
echo "[*] Building GhostRPC for release..."
# Ensure we are in the directory containing Cargo.toml
if [ ! -f "Cargo.toml" ]; then
    echo "[!] Cargo.toml not found in the current directory! Please run this script from the root of the project."
    exit 1
fi

RUSTFLAGS="-C target-cpu=generic" CARGO_TARGET_DIR=/root/target cargo build --release
cp /root/target/release/GhostRPC ./GhostRPC
echo "✅ Build Completed Successfully!"
echo ""
echo "[*] Quick Instructions:"
echo "    Server Mode: ./GhostRPC server.toml"
echo "    Client Mode: ./GhostRPC client.toml"
echo ""
echo "[+] The executable is located at: ./GhostRPC"
echo "==========================================="
