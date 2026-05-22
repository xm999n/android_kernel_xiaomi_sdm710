#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_DIR="${KERNEL_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
PERF_DEPS="${PERF_DEPS:-$SCRIPT_DIR}"

JOBS="${JOBS:-$(nproc)}"
OUT_DIR="${OUT_DIR:-$KERNEL_DIR/out/grus-r536225}"
PERF_OUT="${PERF_OUT:-$OUT_DIR/tools/perf-static}"
CONFIG_SOURCE="${CONFIG_SOURCE:-$KERNEL_DIR/1.md}"

NDK="${NDK:-}"
if [[ -z "$NDK" ]]; then
	if [[ -n "${ANDROID_HOME:-}" && -d "$ANDROID_HOME/ndk/25.1.8937393" ]]; then
		NDK="$ANDROID_HOME/ndk/25.1.8937393"
	else
		NDK="/home/user/android-studio-2025.1.1.14/Android/Sdk/ndk/25.1.8937393"
	fi
fi
NDK_BIN="${NDK_BIN:-$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin}"

CLANG_DIR="${CLANG_DIR:-/home/user/gj/clang-r536225/bin}"
A64_DIR="${A64_DIR:-/home/user/gj/aarch64-linux-android-4.9/bin}"
ARM32_DIR="${ARM32_DIR:-/home/user/gj/arm-linux-androideabi-4.9/bin}"

require_file() {
	local path="$1"
	if [[ ! -e "$path" ]]; then
		echo "missing: $path" >&2
		exit 1
	fi
}

require_file "$NDK_BIN/aarch64-linux-android24-clang"
require_file "$NDK_BIN/aarch64-linux-android24-clang++"
require_file "$NDK_BIN/llvm-ar"
require_file "$NDK_BIN/llvm-ranlib"
require_file "$NDK_BIN/llvm-readelf"
require_file "$CLANG_DIR/clang"
require_file "$CLANG_DIR/clang++"
require_file "$A64_DIR/aarch64-linux-android-ld"
require_file "$ARM32_DIR/arm-linux-androideabi-ld"
require_file "$CONFIG_SOURCE"

fix_perf_deps() {
	chmod +x "$PERF_DEPS/bin/clang-perf-depwrap"
	ln -sfn clang-perf-depwrap "$PERF_DEPS/bin/aarch64-linux-android24-clang"
	ln -sfn clang-perf-depwrap "$PERF_DEPS/bin/aarch64-linux-android24-clang++"

	ln -sfn libelf.so "$PERF_DEPS/lib/libelf.so.1"
	ln -sfn libdw.so "$PERF_DEPS/lib/libdw.so.1"
	ln -sfn libunwind-aarch64.a "$PERF_DEPS/lib/libunwind-generic.a"
	ln -sfn libunwind-aarch64.so "$PERF_DEPS/lib/libunwind-generic.so"

	if [[ -f "$PERF_DEPS/patches/libunwind/elf64.o" ]]; then
		"$NDK_BIN/llvm-ar" r "$PERF_DEPS/lib/libunwind.a" "$PERF_DEPS/patches/libunwind/elf64.o" >/dev/null
		"$NDK_BIN/llvm-ar" r "$PERF_DEPS/lib/libunwind-aarch64.a" "$PERF_DEPS/patches/libunwind/elf64.o" >/dev/null
		"$NDK_BIN/llvm-ranlib" "$PERF_DEPS/lib/libunwind.a"
		"$NDK_BIN/llvm-ranlib" "$PERF_DEPS/lib/libunwind-aarch64.a"
	fi

	for pc in "$PERF_DEPS"/lib/pkgconfig/*.pc; do
		[[ -f "$pc" ]] || continue
		sed -i \
			-e "s#^prefix=.*#prefix=$PERF_DEPS#" \
			-e 's#^exec_prefix=.*#exec_prefix=${prefix}#' \
			-e 's#^libdir=.*#libdir=${exec_prefix}/lib#' \
			-e 's#^includedir=.*#includedir=${prefix}/include#' \
			"$pc"
	done
}

prepare_kernel_headers() {
	mkdir -p "$OUT_DIR"
	cp "$CONFIG_SOURCE" "$OUT_DIR/.config"
	make -C "$KERNEL_DIR" -j"$JOBS" \
		O="$OUT_DIR" \
		ARCH=arm64 \
		CC="$CLANG_DIR/clang" \
		HOSTCC="$CLANG_DIR/clang" \
		HOSTCXX="$CLANG_DIR/clang++" \
		CLANG_TRIPLE=aarch64-linux-gnu- \
		CROSS_COMPILE="$A64_DIR/aarch64-linux-android-" \
		CROSS_COMPILE_ARM32="$ARM32_DIR/arm-linux-androideabi-" \
		LLVM_IAS=1 \
		olddefconfig prepare scripts
}

build_perf_static() {
	mkdir -p "$PERF_OUT"
	"$NDK_BIN/aarch64-linux-android24-clang" \
		-fno-emulated-tls \
		-c "$PERF_DEPS/src/tls-align.c" \
		-o "$PERF_OUT/perf-gj-tls-align.o"
	env \
		PATH="$PERF_DEPS/bin:$NDK_BIN:/usr/bin:/bin" \
		NDK="$NDK" \
		NDK_BIN="$NDK_BIN" \
		PKG_CONFIG_LIBDIR="$PERF_DEPS/lib/pkgconfig:$PERF_DEPS/share/pkgconfig" \
		make -B -C "$KERNEL_DIR/tools/perf" -f Makefile.perf -j"$JOBS" \
		O="$PERF_OUT/" \
		ARCH=arm64 \
		CC="$PERF_DEPS/bin/aarch64-linux-android24-clang" \
		CXX="$PERF_DEPS/bin/aarch64-linux-android24-clang++" \
		AR="$NDK_BIN/llvm-ar" \
		LD="$NDK_BIN/ld.lld" \
		HOSTCC=gcc \
		HOSTCXX=g++ \
		WERROR=0 \
		NO_GTK2=1 \
		NO_LOCAL_LIBUNWIND=1 \
		LIBTRACEEVENT_DYNAMIC_LIST_LDFLAGS= \
		LIBDW_DIR="$PERF_DEPS" \
		LIBUNWIND_DIR="$PERF_DEPS" \
		LIBBABELTRACE_DIR="$PERF_DEPS" \
		LIBUNWIND_LIBS="-lunwind-aarch64 -lunwind -lz" \
		"FEATURE_CHECK_LDFLAGS-libunwind-aarch64=-L$PERF_DEPS/lib -lunwind -lz" \
		"FEATURE_CHECK_LDFLAGS-libunwind-debug-frame-aarch64=-L$PERF_DEPS/lib -lunwind -lz" \
		"EXTLIBS_LIBUNWIND=-lunwind-aarch64 -lunwind -lz" \
		"EXTRA_CFLAGS=-I$PERF_DEPS/include -fcommon -Wno-error=unknown-warning-option -Wno-unknown-warning-option -Wno-error=format -Wno-error=implicit-function-declaration -Wno-error=self-assign" \
		LDFLAGS="-static -L$PERF_DEPS/lib $PERF_OUT/perf-gj-tls-align.o"
}

verify_perf_static() {
	local perf="$PERF_OUT/perf"
	require_file "$perf"
	file "$perf"
	if ! file "$perf" | grep -q "statically linked"; then
		echo "perf is not statically linked" >&2
		exit 1
	fi
	if "$NDK_BIN/llvm-readelf" -d "$perf" | grep -q "NEEDED"; then
		echo "perf has dynamic NEEDED entries" >&2
		"$NDK_BIN/llvm-readelf" -d "$perf" >&2
		exit 1
	fi
	"$NDK_BIN/llvm-readelf" -l "$perf" | grep -q 'TLS.*0x40'
	grep -q '^CONFIG_DWARF=y$' "$PERF_OUT/.config-detected"
	grep -q '^CONFIG_LIBUNWIND_AARCH64=y$' "$PERF_OUT/.config-detected"
	grep -q '^CONFIG_AUDIT=y$' "$PERF_OUT/.config-detected"
	grep -q '^CONFIG_SLANG=y$' "$PERF_OUT/.config-detected"
	echo "static perf ready: $perf"
}

fix_perf_deps
prepare_kernel_headers
build_perf_static
verify_perf_static
