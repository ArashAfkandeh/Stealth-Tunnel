#!/bin/bash
set -e

echo "🚀 Starting Enterprise Build Process..."

cd /root/tunnel

# 1. بررسی و نصب پیش‌نیازهای سیستم‌عامل برای کامپایل استاتیک (musl)
if ! command -v x86_64-linux-musl-gcc &> /dev/null; then
    echo "🔧 'musl-gcc' not found. Attempting to install 'musl-tools'..."
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y musl-tools build-essential
    elif command -v dnf &> /dev/null; then
        dnf install -y musl-gcc
    elif command -v pacman &> /dev/null; then
        pacman -S --noconfirm musl
    else
        echo "❌ Cannot install musl-tools automatically. Please install it manually."
        exit 1
    fi
fi

# 2. بررسی نصب بودن Rust
if ! command -v cargo &> /dev/null; then
    echo "❌ Cargo not found. Please install Rust (https://rustup.rs/)."
    exit 1
fi

# 3. اضافه کردن تارگت musl
echo "📦 Adding x86_64-unknown-linux-musl target..."
rustup target add x86_64-unknown-linux-musl

# 4. کامپایل نسخه Release
echo "⚙️ Building the binary (This may take a few minutes while compiling C/ASM crypto routines)..."
cargo build --release --target x86_64-unknown-linux-musl

# 5. استخراج و فشرده‌سازی باینری
echo "📂 Moving and stripping the binary..."
mkdir -p ./release_bin
cp target/x86_64-unknown-linux-musl/release/stealth_tunnel ./release_bin/
strip ./release_bin/stealth_tunnel # کاهش حجم فایل خروجی با حذف دیباگ‌سیمبل‌ها

echo "✅ Build Completed Successfully!"
echo "📁 Binary is located at: ./release_bin/stealth_tunnel"
