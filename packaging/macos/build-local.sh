#!/bin/sh
# Build a local app bundle without replacing an installed RustGrid.
# Usage: sh packaging/macos/build-local.sh [debug|release]
set -eu

profile="${1:-debug}"
case "$profile" in
    debug|release) ;;
    *) echo "usage: $0 [debug|release]" >&2; exit 2 ;;
esac

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$repo_root"

if [ "$profile" = release ]; then
    cargo build --locked --release -p rustgrid-app
else
    cargo build --locked -p rustgrid-app
fi

version="$(cargo metadata --locked --no-deps --format-version 1 | python3 -c '
import json, sys
packages = json.load(sys.stdin)["packages"]
print(next(p["version"] for p in packages if p["name"] == "rustgrid-app"))
')"
build_root="${CARGO_TARGET_DIR:-$repo_root/target}"
app="$build_root/local/RustGrid SSH.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$build_root/$profile/RustGrid" "$app/Contents/MacOS/RustGrid"
sed "s/@VERSION@/$version/g" packaging/macos/Info.plist > "$app/Contents/Info.plist"
sh packaging/macos/make-icns.sh crates/rustgrid-app/assets/logo_dock.png \
    "$app/Contents/Resources/AppIcon.icns"
plutil -lint "$app/Contents/Info.plist"
codesign --force --sign - "$app"
codesign --verify --deep --strict "$app"
printf 'Built: %s\n' "$app"
