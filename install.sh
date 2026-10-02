#!/usr/bin/env bash

set -e

echo -e "\033[0;34m[BUILD]\033[0m Building binja..."

make

echo -e "\033[0;32m[OK]\033[0m Build successful"

if [ ! -f "./binja" ]; then
    echo -e "\033[0;31m[ERROR]\033[0m binja binary was not created"
    exit 1
fi

echo -e "\033[0;34m[INSTALL]\033[0m Installing binja to /usr/bin..."

sudo mv ./binja /usr/bin/binja
sudo chmod 755 /usr/bin/binja

# Install man page if it exists
if [ -f "./binja.1" ]; then
    echo -e "\033[0;34m[INSTALL]\033[0m Installing man page..."

    sudo mkdir -p /usr/share/man/man1
    sudo cp ./binja.1 /usr/share/man/man1/binja.1
    sudo chmod 644 /usr/share/man/man1/binja.1
fi

# Install documentation if it exists
if [ -f "./README.md" ]; then
    echo -e "\033[0;34m[INSTALL]\033[0m Installing documentation..."

    sudo mkdir -p /usr/share/doc/binja
    sudo cp ./README.md /usr/share/doc/binja/README.md
    sudo chmod 644 /usr/share/doc/binja/README.md
fi

echo ""
echo -e "\033[0;32m✓ binja installed successfully!\033[0m"
echo -e "  Run with: \033[0;33mbinja <binary>\033[0m"
echo ""