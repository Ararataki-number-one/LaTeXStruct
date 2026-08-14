# -*- coding: utf-8 -*-
"""生成 packaging/icon.ico（纯标准库：32x32 RGBA PNG 嵌入 ICO 容器）。"""

import struct
import zlib
from pathlib import Path


def chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def main():
    w = h = 32
    rows = []
    for y in range(h):
        row = bytearray([0])  # filter type 0
        for x in range(w):
            in_square = 4 <= x < 28 and 4 <= y < 28
            stripe = 12 <= y < 20 and 8 <= x < 24
            if in_square and stripe:
                r, g, b, a = 255, 255, 255, 255
            elif in_square:
                r, g, b, a = 37, 99, 235, 255  # 蓝色圆角方块
            else:
                r, g, b, a = 0, 0, 0, 0
            row += bytes((r, g, b, a))
        rows.append(bytes(row))
    raw = b"".join(rows)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )
    ico = (
        struct.pack("<HHH", 0, 1, 1)
        + struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(png), 22)
        + png
    )
    out = Path(__file__).resolve().parent / "icon.ico"
    out.write_bytes(ico)
    print("icon ->", out, len(ico), "bytes")


if __name__ == "__main__":
    main()
