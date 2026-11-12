#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: $1 is required but was not found in PATH." >&2
        exit 1
    fi
}

install_local() {
    local target_dir="$HOME/.local/bin"

    mkdir -p "$target_dir"
    install -m 755 alosint "$target_dir/alosint"
    echo "Installed AlOsint to $target_dir/alosint"

    case ":$PATH:" in
        *":$target_dir:"*) ;;
        *) echo "Add $target_dir to your PATH to run 'alosint' directly." ;;
    esac
}

require_command goose
require_command gcc

echo "Building AlOsint..."
goose build alosint.goose --cc gcc -o alosint

if [ -w /usr/local/bin ]; then
    install -m 755 alosint /usr/local/bin/alosint
    echo "Installed AlOsint to /usr/local/bin/alosint"
elif command -v sudo >/dev/null 2>&1; then
    if sudo install -m 755 alosint /usr/local/bin/alosint; then
        echo "Installed AlOsint to /usr/local/bin/alosint"
    else
        echo "Could not install to /usr/local/bin; falling back to $HOME/.local/bin." >&2
        install_local
    fi
else
    install_local
fi
