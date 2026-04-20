#!/usr/bin/env python3
import argparse
import hashlib
import os
import struct
from pathlib import Path


BOOT_MAGIC = b"ANDROID!"
BOOT_NAME_SIZE = 16
BOOT_ARGS_SIZE = 512
BOOT_EXTRA_ARGS_SIZE = 1024
BOOT_ID_SIZE = 32
HEADER_V2_SIZE = 1660


def align(value: int, page_size: int) -> int:
    return (value + page_size - 1) // page_size * page_size


def c_string(data: bytes) -> bytes:
    return data.split(b"\0", 1)[0]


def pack_c_string(data: bytes, size: int) -> bytes:
    if len(data) > size:
        raise ValueError(f"field too large: {len(data)} > {size}")
    return data + b"\0" * (size - len(data))


def split_cmdline(cmdline: bytes) -> tuple[bytes, bytes]:
    if len(cmdline) > BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE:
        raise ValueError("combined cmdline is larger than boot header capacity")
    first = cmdline[:BOOT_ARGS_SIZE]
    rest = cmdline[BOOT_ARGS_SIZE:]
    return first, rest


def sha1_boot_id(parts: list[bytes]) -> bytes:
    sha = hashlib.sha1()
    for part in parts:
        sha.update(part)
        sha.update(struct.pack("<I", len(part)))
    digest = sha.digest()
    return digest + b"\0" * (BOOT_ID_SIZE - len(digest))


def parse_boot_image(path: Path) -> dict:
    data = path.read_bytes()
    if data[:8] != BOOT_MAGIC:
        raise ValueError(f"{path} is not an Android boot image")

    fields = struct.unpack("<10I", data[8:48])
    kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, second_size, second_addr, tags_addr, page_size, header_version, os_version = fields
    if header_version != 2:
        raise ValueError(f"only boot header v2 is supported, got v{header_version}")

    name = c_string(data[48:64])
    cmdline = c_string(data[64:64 + BOOT_ARGS_SIZE])
    boot_id = data[64 + BOOT_ARGS_SIZE:64 + BOOT_ARGS_SIZE + BOOT_ID_SIZE]
    extra_cmdline_off = 64 + BOOT_ARGS_SIZE + BOOT_ID_SIZE
    extra_cmdline = c_string(data[extra_cmdline_off:extra_cmdline_off + BOOT_EXTRA_ARGS_SIZE])

    v1_off = 1632
    recovery_dtbo_size = struct.unpack("<I", data[v1_off:v1_off + 4])[0]
    recovery_dtbo_offset = struct.unpack("<Q", data[v1_off + 4:v1_off + 12])[0]
    header_size = struct.unpack("<I", data[v1_off + 12:v1_off + 16])[0]
    dtb_size = struct.unpack("<I", data[v1_off + 16:v1_off + 20])[0]
    dtb_addr = struct.unpack("<Q", data[v1_off + 20:v1_off + 28])[0]

    if header_size != HEADER_V2_SIZE:
        raise ValueError(f"unexpected boot header size: {header_size}")

    kernel_off = page_size
    ramdisk_off = kernel_off + align(kernel_size, page_size)
    second_off = ramdisk_off + align(ramdisk_size, page_size)
    recovery_dtbo_off = second_off + align(second_size, page_size)
    dtb_off = recovery_dtbo_off + align(recovery_dtbo_size, page_size)

    return {
        "raw": data,
        "kernel": data[kernel_off:kernel_off + kernel_size],
        "ramdisk": data[ramdisk_off:ramdisk_off + ramdisk_size],
        "second": data[second_off:second_off + second_size],
        "recovery_dtbo": data[recovery_dtbo_off:recovery_dtbo_off + recovery_dtbo_size],
        "dtb": data[dtb_off:dtb_off + dtb_size],
        "name": name,
        "cmdline": cmdline + extra_cmdline,
        "id": boot_id,
        "page_size": page_size,
        "kernel_addr": kernel_addr,
        "ramdisk_addr": ramdisk_addr,
        "second_addr": second_addr,
        "tags_addr": tags_addr,
        "header_version": header_version,
        "os_version": os_version,
        "recovery_dtbo_offset": recovery_dtbo_offset,
        "dtb_addr": dtb_addr,
    }


def build_boot_image(meta: dict, kernel: bytes, dtb: bytes) -> bytes:
    cmd_first, cmd_extra = split_cmdline(meta["cmdline"])
    ramdisk = meta["ramdisk"]
    second = meta["second"]
    recovery_dtbo = meta["recovery_dtbo"]

    boot_id = sha1_boot_id([kernel, ramdisk, second, recovery_dtbo, dtb])

    header = bytearray()
    header += BOOT_MAGIC
    header += struct.pack(
        "<10I",
        len(kernel),
        meta["kernel_addr"],
        len(ramdisk),
        meta["ramdisk_addr"],
        len(second),
        meta["second_addr"],
        meta["tags_addr"],
        meta["page_size"],
        meta["header_version"],
        meta["os_version"],
    )
    header += pack_c_string(meta["name"], BOOT_NAME_SIZE)
    header += pack_c_string(cmd_first, BOOT_ARGS_SIZE)
    header += boot_id
    header += pack_c_string(cmd_extra, BOOT_EXTRA_ARGS_SIZE)
    header += struct.pack("<I", len(recovery_dtbo))
    header += struct.pack("<Q", 0 if not recovery_dtbo else 0)
    header += struct.pack("<I", HEADER_V2_SIZE)
    header += struct.pack("<I", len(dtb))
    header += struct.pack("<Q", meta["dtb_addr"])

    if len(header) != HEADER_V2_SIZE:
        raise ValueError(f"packed header size mismatch: {len(header)}")

    page_size = meta["page_size"]
    image = bytearray()
    image += header
    image += b"\0" * (align(len(image), page_size) - len(image))

    for part in [kernel, ramdisk, second, recovery_dtbo, dtb]:
        if not part:
            continue
        image += part
        image += b"\0" * (align(len(part), page_size) - len(part))

    return bytes(image)


def main() -> None:
    parser = argparse.ArgumentParser(description="Repack a boot.img with a new kernel and dtb payload")
    parser.add_argument("--boot", required=True, help="original boot.img")
    parser.add_argument("--kernel", required=True, help="new kernel Image")
    parser.add_argument("--dtb", action="append", default=[], help="dtb file to append; pass multiple times in desired order")
    parser.add_argument("--output", required=True, help="output boot image path")
    args = parser.parse_args()

    boot_path = Path(args.boot)
    kernel_path = Path(args.kernel)
    output_path = Path(args.output)
    dtb_paths = [Path(p) for p in args.dtb]

    meta = parse_boot_image(boot_path)
    kernel = kernel_path.read_bytes()
    dtb = b"".join(path.read_bytes() for path in dtb_paths)

    image = build_boot_image(meta, kernel, dtb)
    output_path.write_bytes(image)

    print(f"wrote: {output_path}")
    print(f"page_size: {meta['page_size']}")
    print(f"kernel: {kernel_path} ({len(kernel)} bytes)")
    print(f"dtb parts: {len(dtb_paths)}")
    for path in dtb_paths:
        print(f"  - {path} ({path.stat().st_size} bytes)")
    print(f"dtb total: {len(dtb)} bytes")
    print(f"ramdisk preserved: {len(meta['ramdisk'])} bytes")
    print("note: this output does not regenerate AVB metadata/footer from the original image")


if __name__ == "__main__":
    main()
