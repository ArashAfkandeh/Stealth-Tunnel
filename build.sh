#!/bin/bash
set -e
echo "🚀 Starting Enterprise Build Process (Native/Dynamic GNU)..."

# وارد شدن به پوشه صحیح پروژه (جلوگیری از اجرای نسخه قبلی اسکریپت)
cd "$(dirname "$0")"

# 1. نصب پیش‌نیازهای کامپایل BoringSSL روی لینوکس استاندارد (Glibc)
if command -v apt-get &> /dev/null; then
    echo "🔧 Installing native build dependencies (g++, cmake, golang, etc.)..."
    apt-get update
    # نصب نسخه‌های استاندارد ابزارهای کامپایل به جای musl
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" build-essential cmake golang clang pkg-config libssl-dev g++ git ninja-build curl
elif command -v dnf &> /dev/null; then
    echo "🔧 Installing native build dependencies (gcc-c++, cmake, golang, etc.)..."
    dnf install -y gcc-c++ cmake golang clang pkgconf-pkg-config openssl-devel git ninja-build curl
elif command -v pacman &> /dev/null; then
    echo "🔧 Installing native build dependencies for Arch Linux..."
    pacman -Sy --noconfirm base-devel cmake go clang pkgconf openssl git ninja curl
fi

# 2. بررسی و نصب خودکار Rust
if ! command -v cargo &> /dev/null; then
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env" || . "$HOME/.cargo/env"
    else
        echo "🦀 Cargo is missing. Installing Rust automatically..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env" || . "$HOME/.cargo/env"
    fi
fi

# 3. کامپایل نسخه Release (حذف تارگت musl برای حل مشکل boring-sys)
# توجه: به دلیل پیچیدگی‌های BoringSSL، بیلد به صورت داینامیک روی لینوکس انجام می‌شود.
echo "⚙️ Building the binary natively (This may take a few minutes)..."
cargo build --release

# 4. استخراج و فشرده‌سازی باینری
echo "📂 Moving and stripping the binary..."
mkdir -p ./release_bin
cp target/release/stealth_tunnel ./release_bin/
strip ./release_bin/stealth_tunnel || true # کاهش حجم فایل خروجی

echo "✅ Build Completed Successfully!"
echo "📁 Binary is located at: ./release_bin/stealth_tunnel"
