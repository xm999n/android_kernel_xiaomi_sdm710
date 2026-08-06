#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/out/grus}"
CONFIG_SOURCE="${CONFIG_SOURCE:-$ROOT_DIR/1.md}"
JOBS="${JOBS:-$(nproc)}"

die() {
  echo "error: $*" >&2
  exit 1
}

require_file() {
  local path="$1"
  [[ -f "$path" ]] || die "missing file: $path"
}

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || die "missing command: $cmd"
}

select_clang_bin_dir() {
  if [[ -n "${CLANG_DIR:-}" ]]; then
    [[ -x "$CLANG_DIR/clang" ]] || die "CLANG_DIR does not contain clang: $CLANG_DIR"
    printf '%s\n' "$CLANG_DIR"
    return
  fi

  if command -v clang-19 >/dev/null 2>&1; then
    dirname "$(command -v clang-19)"
    return
  fi

  if command -v clang >/dev/null 2>&1; then
    dirname "$(command -v clang)"
    return
  fi

  die "clang not found; set CLANG_DIR to a toolchain bin directory"
}

select_prefix() {
  local dir_var_name="$1"
  local preferred_prefix="$2"
  local fallback_prefix="$3"
  local dir_value="${!dir_var_name:-}"

  if [[ -n "$dir_value" ]]; then
    if [[ -x "$dir_value/${preferred_prefix}ld" ]]; then
      printf '%s%s\n' "$dir_value/" "$preferred_prefix"
      return
    fi

    if [[ -x "$dir_value/${fallback_prefix}ld" ]]; then
      printf '%s%s\n' "$dir_value/" "$fallback_prefix"
      return
    fi

    die "$dir_var_name does not contain ${preferred_prefix}ld or ${fallback_prefix}ld: $dir_value"
  fi

  if command -v "${preferred_prefix}ld" >/dev/null 2>&1; then
    printf '%s\n' "$preferred_prefix"
    return
  fi

  if command -v "${fallback_prefix}ld" >/dev/null 2>&1; then
    printf '%s\n' "$fallback_prefix"
    return
  fi

  die "missing toolchain prefix; set $dir_var_name to a bin directory containing ${preferred_prefix}ld or ${fallback_prefix}ld"
}

CLANG_BIN_DIR="$(select_clang_bin_dir)"
A64_PREFIX="$(select_prefix A64_DIR aarch64-linux-android- aarch64-linux-gnu-)"
ARM32_PREFIX="$(select_prefix ARM32_DIR arm-linux-androideabi- arm-linux-gnueabi-)"

CC_BIN="$CLANG_BIN_DIR/clang"
HOSTCC_BIN="$CLANG_BIN_DIR/clang"
HOSTCXX_BIN="$CLANG_BIN_DIR/clang++"

require_file "$CONFIG_SOURCE"
require_file "$CC_BIN"
require_file "$HOSTCXX_BIN"
require_cmd "${A64_PREFIX}ld"
require_cmd "${A64_PREFIX}ar"
require_cmd "${A64_PREFIX}nm"
require_cmd "${ARM32_PREFIX}ld"
require_cmd "${ARM32_PREFIX}ar"
require_cmd "${ARM32_PREFIX}nm"

mkdir -p "$OUT_DIR"
cp "$CONFIG_SOURCE" "$OUT_DIR/.config"

echo "== v4l2loopback source =="
# drivers/Makefile references drivers/virtual_camera via obj-y; ensure the
# directory exists before kbuild scans it. In CI the checkout won't have it
# (it's an independent repo), so clone upstream when missing.
VC_DIR="$ROOT_DIR/drivers/virtual_camera"
if [[ ! -f "$VC_DIR/v4l2loopback.c" ]]; then
  rm -rf "$VC_DIR"
  git clone --depth 1 https://github.com/umlaeute/v4l2loopback.git "$VC_DIR"
else
  echo "v4l2loopback source already present, skipping clone"
fi

echo "== Toolchains =="
echo "CLANG_BIN_DIR=$CLANG_BIN_DIR"
echo "A64_PREFIX=$A64_PREFIX"
echo "ARM32_PREFIX=$ARM32_PREFIX"
echo
"$CC_BIN" --version | sed -n '1,3p'
echo

make_args=(
  O="$OUT_DIR"
  ARCH=arm64
  CC="$CC_BIN"
  HOSTCC="$HOSTCC_BIN"
  HOSTCXX="$HOSTCXX_BIN"
  LLVM_IAS=1
  CLANG_TRIPLE=aarch64-linux-gnu-
  CROSS_COMPILE="$A64_PREFIX"
  CROSS_COMPILE_ARM32="$ARM32_PREFIX"
)

echo "== olddefconfig =="
make "${make_args[@]}" olddefconfig
echo

echo "== build =="
make -j"$JOBS" "${make_args[@]}" Image.gz dtbs modules
echo

echo "== sign modules =="
# CONFIG_MODULE_SIG_FORCE=y requires .ko to be signed; CONFIG_MODULE_SIG_ALL=y
# should auto-sign during modules_install but not always during plain `modules`,
# so sign explicitly here to be safe. Hash matches CONFIG_MODULE_SIG_HASH.
SIG_HASH="sha512"
SIGN_KEY="$OUT_DIR/certs/signing_key.pem"
SIGN_X509="$OUT_DIR/certs/signing_key.x509"
SIGN_TOOL="$OUT_DIR/scripts/sign-file"
[[ -f "$SIGN_KEY"  ]] || die "missing signing key: $SIGN_KEY"
[[ -f "$SIGN_X509" ]] || die "missing signing cert: $SIGN_X509"
[[ -x "$SIGN_TOOL" ]] || die "missing sign-file tool: $SIGN_TOOL"
ko_count=0
while IFS= read -r -d '' ko; do
  "$SIGN_TOOL" "$SIG_HASH" "$SIGN_KEY" "$SIGN_X509" "$ko"
  ko_count=$((ko_count+1))
done < <(find "$OUT_DIR" -name '*.ko' -print0)
echo "signed $ko_count module(s)"
echo

echo "== Outputs =="
printf '%s\n' \
  "$OUT_DIR/arch/arm64/boot/Image.gz" \
  "$OUT_DIR/arch/arm64/boot/dts/qcom/sdm710.dtb" \
  "$OUT_DIR/arch/arm64/boot/dts/qcom/grus-sdm710-overlay.dtbo"
