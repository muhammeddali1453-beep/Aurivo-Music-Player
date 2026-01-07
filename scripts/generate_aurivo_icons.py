#!/usr/bin/env python3
"""Aurivo ikon setini (16..512) otomatik üretir.

Amaç: Menüde "küçük" görünen ikonu, logonun gerçek alanına göre crop edip
tekrar kareleyerek (square-pad) farklı boyutlara yeniden örneklemek.

Çalıştırma:
  ./pyqt_venv/bin/python scripts/generate_aurivo_icons.py

Notlar:
- Kaynak olarak öncelikle icons/aurivo_alt_clean_1024.png kullanır.
- Maske, alpha yerine parlaklık/saturation üzerinden çıkarılır (arka plan koyu/solid ise).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PIL import Image

try:
    import numpy as np
except Exception:  # pragma: no cover
    np = None


ROOT = Path(__file__).resolve().parents[1]
ICONS_DIR = ROOT / "icons"


@dataclass(frozen=True)
class IconSource:
    path: Path
    background_rgb: tuple[int, int, int]


def _pick_source() -> IconSource:
    # Tercih sırası: daha "dolu" görünen varyantlar
    candidates = [
        ICONS_DIR / "aurivo_alt_clean_1024.png",
        ICONS_DIR / "aurivo_app_1024.png",
        ICONS_DIR / "aurivo_512.png",
        ICONS_DIR / "aurivo.png",
    ]
    for p in candidates:
        if p.exists():
            # Arka plan rengi: köşeler genelde solid.
            im = Image.open(p).convert("RGBA")
            w, h = im.size
            corners = [
                im.getpixel((0, 0))[:3],
                im.getpixel((w - 1, 0))[:3],
                im.getpixel((0, h - 1))[:3],
                im.getpixel((w - 1, h - 1))[:3],
            ]
            # Median benzeri: basit çoğunluk/ortalama
            bg = tuple(int(sum(c[i] for c in corners) / 4) for i in range(3))
            return IconSource(path=p, background_rgb=bg)
    raise FileNotFoundError("Kaynak ikon bulunamadı (icons/aurivo*_*.png).")


def _compute_content_bbox(im: Image.Image, bg_rgb: tuple[int, int, int]) -> tuple[int, int, int, int]:
    """Koyu arka plan üzerinde logonun bbox'unu tahmin eder."""
    if np is None:
        # NumPy yoksa kaba bir eşikleme (daha yavaş ama çalışır)
        w, h = im.size
        thr_v = 42  # 0..255
        xs, ys = [], []
        for y in range(h):
            for x in range(w):
                r, g, b, a = im.getpixel((x, y))
                if a == 0:
                    continue
                v = max(r, g, b)
                if v >= thr_v:
                    xs.append(x)
                    ys.append(y)
        if not xs:
            return (0, 0, im.size[0], im.size[1])
        return (min(xs), min(ys), max(xs) + 1, max(ys) + 1)

    arr = np.array(im.convert("RGBA"), dtype=np.uint8)
    rgb = arr[:, :, :3].astype(np.int16)
    alpha = arr[:, :, 3]

    # HSV benzeri: V ve S (yaklaşık)
    mx = rgb.max(axis=2)
    mn = rgb.min(axis=2)
    v = mx.astype(np.float32) / 255.0
    s = np.zeros_like(v)
    nonzero = mx > 0
    s[nonzero] = (mx[nonzero] - mn[nonzero]).astype(np.float32) / mx[nonzero].astype(np.float32)

    H, W = v.shape

    def bbox_for(v_thr: float, s_thr: float):
        mask = (alpha > 0) & (v > v_thr) & (s > s_thr)
        if not mask.any():
            return None, 0.0
        ys, xs = np.where(mask)
        x0, x1 = int(xs.min()), int(xs.max()) + 1
        y0, y1 = int(ys.min()), int(ys.max()) + 1
        ratio = ((x1 - x0) * (y1 - y0)) / float(H * W)
        return (x0, y0, x1, y1), ratio

    # Arka plan gradient/texture ise basit "bg farkı" tüm alanı kapsayabilir.
    # Bu nedenle daha çok "renkli/parlak" bölgeyi hedefleyen adaptif eşikler kullanıyoruz.
    candidates = [
        (0.30, 0.10),
        (0.25, 0.10),
        (0.22, 0.10),
        (0.20, 0.08),  # pratikte en iyi çalışan eşik
        (0.18, 0.10),
        (0.16, 0.12),
    ]

    for v_thr, s_thr in candidates:
        bb, ratio = bbox_for(v_thr, s_thr)
        if bb is None:
            continue
        # Çok küçük bbox: logo parçası seçilmiş olabilir.
        if ratio < 0.10:
            continue
        # Çok büyük bbox: arka plan seçilmiş olabilir.
        if ratio > 0.90:
            continue
        return bb

    # Fallback: en azından bir bbox döndür
    bb, _ = bbox_for(0.20, 0.08)
    if bb is not None:
        return bb
    return (0, 0, im.size[0], im.size[1])


def _expand_bbox(bbox: tuple[int, int, int, int], size: tuple[int, int], pad_frac: float = 0.06) -> tuple[int, int, int, int]:
    x0, y0, x1, y1 = bbox
    w = x1 - x0
    h = y1 - y0
    pad = int(max(w, h) * pad_frac)

    W, H = size
    x0 = max(0, x0 - pad)
    y0 = max(0, y0 - pad)
    x1 = min(W, x1 + pad)
    y1 = min(H, y1 + pad)
    return (x0, y0, x1, y1)


def _square_pad(im: Image.Image, bg_rgb: tuple[int, int, int]) -> Image.Image:
    w, h = im.size
    side = max(w, h)
    bg = (*bg_rgb, 255)
    out = Image.new("RGBA", (side, side), bg)
    out.paste(im, ((side - w) // 2, (side - h) // 2))
    return out


def main() -> None:
    src = _pick_source()
    im = Image.open(src.path).convert("RGBA")

    bbox = _compute_content_bbox(im, src.background_rgb)
    bbox = _expand_bbox(bbox, im.size, pad_frac=0.06)

    cropped = im.crop(bbox)
    squared = _square_pad(cropped, src.background_rgb)

    sizes = [16, 24, 32, 48, 64, 128, 256, 512]
    for s in sizes:
        out = squared.resize((s, s), Image.Resampling.LANCZOS)
        out_path = ICONS_DIR / f"aurivo_{s}.png"
        out.save(out_path, optimize=True)

    # Varsayılan aurivo.png: 256
    (ICONS_DIR / "aurivo.png").write_bytes((ICONS_DIR / "aurivo_256.png").read_bytes())

    print("OK: ikon seti üretildi")
    print(f"- Kaynak: {src.path.relative_to(ROOT)} (bg={src.background_rgb})")
    print(f"- Crop bbox: {bbox}")
    print("- Çıktılar: icons/aurivo_{16,24,32,48,64,128,256,512}.png ve icons/aurivo.png")


if __name__ == "__main__":
    main()
