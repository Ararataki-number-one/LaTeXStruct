# -*- coding: utf-8 -*-
"""Build the checked-in Windows and web icons from the approved source artwork.

This is a maintainer utility, not part of the application runtime. Pillow is
used deliberately here so every small Windows icon is downsampled from one
RGBA master with a high-quality Lanczos filter.
"""

from __future__ import annotations

from pathlib import Path

try:
    from PIL import Image
except ImportError as exc:  # pragma: no cover - maintainer dependency guard
    raise SystemExit("Pillow is required: python -m pip install Pillow") from exc


PACKAGING_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKAGING_DIR.parent
SOURCE = PACKAGING_DIR / "icon-source.png"
MASTER_PNG = PACKAGING_DIR / "icon.png"
ICO_PATH = PACKAGING_DIR / "icon.ico"
WEB_DIR = REPO_ROOT / "frontend" / "public"

ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
WEB_SIZES = (32, 64, 180, 192, 512)


def _normalised_master(source: Image.Image, size: int = 1024) -> Image.Image:
    """Crop transparent imbalance and keep a consistent safe edge around the mark."""
    rgba = source.convert("RGBA")
    alpha_bbox = rgba.getchannel("A").getbbox()
    if alpha_bbox is None:
        raise ValueError("icon-source.png is fully transparent")

    visible = rgba.crop(alpha_bbox)
    edge = max(visible.size)
    padding = max(1, round(edge * 0.055))
    canvas_size = edge + padding * 2
    canvas = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    canvas.alpha_composite(
        visible,
        ((canvas_size - visible.width) // 2, (canvas_size - visible.height) // 2),
    )
    return canvas.resize((size, size), Image.Resampling.LANCZOS)


def _save_png(master: Image.Image, path: Path, size: int) -> None:
    image = master if master.size == (size, size) else master.resize(
        (size, size), Image.Resampling.LANCZOS
    )
    image.save(path, format="PNG", optimize=True)


def main() -> None:
    if not SOURCE.is_file():
        raise SystemExit(f"missing approved source artwork: {SOURCE}")

    with Image.open(SOURCE) as source:
        if source.width < 1024 or source.height < 1024:
            raise SystemExit("source artwork must be at least 1024 x 1024")
        master = _normalised_master(source)

    WEB_DIR.mkdir(parents=True, exist_ok=True)
    _save_png(master, MASTER_PNG, 512)
    for size in WEB_SIZES:
        name = "favicon-32.png" if size == 32 else f"app-icon-{size}.png"
        _save_png(master, WEB_DIR / name, size)

    master.save(
        ICO_PATH,
        format="ICO",
        sizes=[(size, size) for size in ICO_SIZES],
        bitmap_format="png",
    )

    print(f"source: {SOURCE}")
    print(f"windows: {ICO_PATH} ({', '.join(map(str, ICO_SIZES))} px)")
    print(f"web: {WEB_DIR} ({', '.join(map(str, WEB_SIZES))} px)")


if __name__ == "__main__":
    main()
