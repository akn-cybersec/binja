#!/usr/bin/env bash

set -e

BINARY="/usr/bin/binja"
MANPAGE="/usr/share/man/man1/binja.1"
DOCDIR="/usr/share/doc/binja"

echo -e "\033[0;31m[REMOVE]\033[0m Uninstalling binja..."

# Remove binary
if [ -f "$BINARY" ]; then
    sudo rm -f "$BINARY"
    echo -e "\033[0;32m[OK]\033[0m Removed $BINARY"
else
    echo -e "\033[0;33m[SKIP]\033[0m Binary not found"
fi

# Remove man page
if [ -f "$MANPAGE" ]; then
    sudo rm -f "$MANPAGE"
    echo -e "\033[0;32m[OK]\033[0m Removed $MANPAGE"
fi

# Remove documentation
if [ -d "$DOCDIR" ]; then
    sudo rm -rf "$DOCDIR"
    echo -e "\033[0;32m[OK]\033[0m Removed $DOCDIR"
fi

echo ""
echo -e "\033[0;32m✓ binja uninstalled successfully!\033[0m"
echo ""