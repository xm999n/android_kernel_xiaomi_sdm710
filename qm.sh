#!/usr/bin/env bash
# Sign kernel modules (.ko) with the kernel build's auto-generated key.
#
# Usage: qm.sh [ko_path] [out_dir]
#   ko_path  - a directory containing .ko files, or a single .ko file.
#              Default: out/grus-r536225
#   out_dir  - kernel build output directory (holds certs/ and scripts/sign-file).
#              Default: out/grus-r536225
#
# Examples:
#   ./qm.sh                                        # sign all .ko under out/grus-r536225
#   ./qm.sh out/grus                               # sign all .ko under out/grus
#   ./qm.sh path/to/v4l2loopback.ko out/grus       # sign a single .ko
set -euo pipefail

KO_PATH="${1:-out/grus-r536225}"
OUT_DIR="${2:-out/grus-r536225}"
SIG_HASH="sha512"
SIGN_KEY="$OUT_DIR/certs/signing_key.pem"
SIGN_X509="$OUT_DIR/certs/signing_key.x509"
SIGN_TOOL="$OUT_DIR/scripts/sign-file"

[[ -f "$SIGN_KEY"  ]] || { echo "error: missing signing key: $SIGN_KEY"   >&2; exit 1; }
[[ -f "$SIGN_X509" ]] || { echo "error: missing signing cert: $SIGN_X509" >&2; exit 1; }
[[ -x "$SIGN_TOOL" ]] || { echo "error: missing sign-file: $SIGN_TOOL"    >&2; exit 1; }

if [[ -f "$KO_PATH" ]]; then
  "$SIGN_TOOL" "$SIG_HASH" "$SIGN_KEY" "$SIGN_X509" "$KO_PATH"
  echo "signed 1 module: $KO_PATH"
elif [[ -d "$KO_PATH" ]]; then
  count=0
  while IFS= read -r -d '' ko; do
    "$SIGN_TOOL" "$SIG_HASH" "$SIGN_KEY" "$SIGN_X509" "$ko"
    count=$((count+1))
  done < <(find "$KO_PATH" -name '*.ko' -print0)
  echo "signed $count module(s) under $KO_PATH"
else
  echo "error: not a file or directory: $KO_PATH" >&2
  exit 1
fi
