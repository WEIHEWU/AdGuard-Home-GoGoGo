#!/bin/sh
set -e
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODULE_PROP="$ROOT_DIR/module/module.prop"
PROP_VER="$(sed -n 's/^version=//p' "$MODULE_PROP" 2>/dev/null | head -n 1)"
VERSION_DATE="${1:-$PROP_VER}"

if [ -z "$VERSION_DATE" ]; then
  echo "ERROR: Could not determine module version from $MODULE_PROP" >&2
  exit 1
fi
if [ "$PROP_VER" != "$VERSION_DATE" ]; then
  echo "ERROR: Version mismatch: module.prop=$PROP_VER != target=$VERSION_DATE" >&2
  exit 1
fi

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "unavailable"
  fi
}

CORE_BIN="$ROOT_DIR/module/bin/AdGuardHome"
if [ ! -s "$CORE_BIN" ]; then
  echo "ERROR: Missing or empty Core binary at $CORE_BIN" >&2
  exit 1
fi
CORE_VER="$(strings "$CORE_BIN" 2>/dev/null | grep -E '^v20[0-9]{2}-[0-9]{2}-[0-9]{2}' | head -n 1 || true)"
CORE_SHA="$(hash_file "$CORE_BIN")"

APK_FILE="$ROOT_DIR/module/AdGuardHomeManager.apk"
if [ ! -s "$APK_FILE" ]; then
  echo "ERROR: Missing or empty Manager APK at $APK_FILE" >&2
  exit 1
fi
APK_SHA="$(hash_file "$APK_FILE")"
AAPT2_BIN=""
if command -v aapt2 >/dev/null 2>&1; then
  AAPT2_BIN="$(command -v aapt2)"
elif [ -d "$HOME/Library/Android/sdk/build-tools" ]; then
  AAPT2_BIN="$(ls -1 "$HOME"/Library/Android/sdk/build-tools/*/aapt2 2>/dev/null | tail -n 1 || true)"
fi
APK_META="unavailable"
if [ -n "$AAPT2_BIN" ] && [ -x "$AAPT2_BIN" ]; then
  APK_META="$("$AAPT2_BIN" dump badging "$APK_FILE" 2>/dev/null | head -n 1 || echo unavailable)"
fi

echo "=== Embedded Artifact Verification ==="
echo "Module : $PROP_VER"
echo "Core   : ${CORE_VER:-unknown} (sha256=$CORE_SHA)"
echo "Manager: $APK_META (sha256=$APK_SHA)"

mkdir -p "$ROOT_DIR/releases"
OUT_ZIP="$ROOT_DIR/releases/AdGuard_Home_gogogo_${VERSION_DATE}.zip"

echo "Building Unified Package (AdGuard-Home-GoGoGo -> AdGuard_Home_gogogo_${VERSION_DATE}.zip)..."
(
  cd "$ROOT_DIR/module"
  rm -f "$OUT_ZIP"
  zip -q -r "$OUT_ZIP" . -x "*.DS_Store" -x "__MACOSX/*"
)

ZIP_SHA="$(hash_file "$OUT_ZIP")"
echo "Done! Package generated in $ROOT_DIR/releases/ (sha256=$ZIP_SHA)"
ls -lh "$ROOT_DIR/releases/"
