#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Aurivo uygulama simgesi üreticisi.

Telif riski olmaması için sıfırdan, özgün bir ikon çizer.
Çıktılar:
  - icons/aurivo_app_1024.png (master)
  - icons/aurivo.png (256)
  - icons/aurivo.ico (Windows)
"""

from __future__ import annotations

import os
from typing import Iterable, Tuple

from PIL import Image, ImageDraw, ImageFilter, ImageFont


ROOT = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(ROOT, "icons")


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return lo if x < lo else hi if x > hi else x


def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def _lerp_rgb(c0: Tuple[int, int, int], c1: Tuple[int, int, int], t: float) -> Tuple[int, int, int]:
    t = _clamp(t)
    return (
        int(round(_lerp(c0[0], c1[0], t))),
        int(round(_lerp(c0[1], c1[1], t))),
        int(round(_lerp(c0[2], c1[2], t))),
    )


def _rainbow(t: float) -> Tuple[int, int, int]:
    """Kırmızı → sarı → yeşil → cyan → mavi → mor."""
    stops = [
        (0.00, (255, 61, 0)),
        (0.20, (255, 214, 0)),
        (0.40, (0, 230, 118)),
        (0.60, (64, 196, 255)),
        (0.80, (124, 77, 255)),
        (1.00, (255, 64, 129)),
    ]
    t = _clamp(t)
    for i in range(len(stops) - 1):
        t0, c0 = stops[i]
        t1, c1 = stops[i + 1]
        if t0 <= t <= t1:
            local = 0.0 if t1 == t0 else (t - t0) / (t1 - t0)
            return _lerp_rgb(c0, c1, local)
    return stops[-1][1]


def _radial_glow(size: int, center: Tuple[float, float], radius: float, color: Tuple[int, int, int], strength: float) -> Image.Image:
    """Basit radyal glow katmanı."""
    cx, cy = center
    glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    px = glow.load()
    r2 = max(1e-6, radius * radius)
    for y in range(size):
        dy = (y - cy)
        for x in range(size):
            dx = (x - cx)
            d2 = dx * dx + dy * dy
            t = d2 / r2
            if t >= 1.0:
                continue
            a = int(round(255 * strength * (1.0 - t) ** 1.8))
            if a <= 0:
                continue
            px[x, y] = (color[0], color[1], color[2], a)
    return glow.filter(ImageFilter.GaussianBlur(radius=max(1, int(round(size * 0.01)))))


def _draw_rainbow_arc_layer(
    size: int,
    box: Tuple[float, float, float, float],
    start: float,
    end: float,
    width: int,
    alpha: int,
    steps: int = 48,
    blur_radius: float = 0.0,
) -> Image.Image:
    layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    steps = max(8, int(steps))
    for i in range(steps):
        t0 = i / steps
        t1 = (i + 1) / steps
        a0 = _lerp(start, end, t0)
        a1 = _lerp(start, end, t1)
        r, g, b = _rainbow(i / max(1, steps - 1))
        d.arc(box, start=a0, end=a1, fill=(r, g, b, int(alpha)), width=int(width))
    if blur_radius and blur_radius > 0:
        layer = layer.filter(ImageFilter.GaussianBlur(radius=blur_radius))
    return layer


def _rounded_rect_mask(w: int, h: int, radius: int, inset: int = 0) -> Image.Image:
    m = Image.new("L", (w, h), 0)
    d = ImageDraw.Draw(m)
    x0, y0 = inset, inset
    x1, y1 = w - inset - 1, h - inset - 1
    rr = max(0, int(radius) - int(inset))
    d.rounded_rectangle([x0, y0, x1, y1], radius=rr, fill=255)
    return m


def _linear_rainbow(w: int, h: int, alpha: int, horizontal: bool = True) -> Image.Image:
    im = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    px = im.load()
    if horizontal:
        for x in range(w):
            r, g, b = _rainbow(x / max(1, w - 1))
            for y in range(h):
                px[x, y] = (r, g, b, int(alpha))
    else:
        for y in range(h):
            r, g, b = _rainbow(y / max(1, h - 1))
            for x in range(w):
                px[x, y] = (r, g, b, int(alpha))
    return im


def make_master_icon(size: int = 1024, variant: str = "default") -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))

    variant = (variant or "default").strip().lower()
    if variant not in {"default", "bold_a", "clean"}:
        variant = "default"

    # Varyasyon ayarları (küçükte okunabilirlik için sadeleşme + A imzası)
    if variant == "bold_a":
        aura_1 = 0.52
        aura_2 = 0.44
        vignette = 0.50
        a_boost = 1.25
        a_glow = 0.25
        bar_count = 11
        bar_alpha = 245
        hp_arc_alpha = 170
        hp_pad_alpha = 120
    elif variant == "clean":
        aura_1 = 0.38
        aura_2 = 0.30
        vignette = 0.62
        a_boost = 1.10
        a_glow = 0.10
        bar_count = 9
        bar_alpha = 230
        hp_arc_alpha = 120
        hp_pad_alpha = 80
    else:
        aura_1 = 0.45
        aura_2 = 0.38
        vignette = 0.55
        a_boost = 1.00
        a_glow = 0.18
        bar_count = 11
        bar_alpha = 235
        hp_arc_alpha = 150
        hp_pad_alpha = 100

    # Arka plan: koyu rounded-square
    bg = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(bg)
    margin = int(round(size * 0.06))
    radius = int(round(size * 0.18))
    d.rounded_rectangle(
        [margin, margin, size - margin, size - margin],
        radius=radius,
        fill=(14, 14, 16, 255),
    )

    # Aura glow (Aurivo teması: mavi + mor)
    glow1 = _radial_glow(size, (size * 0.45, size * 0.40), size * 0.55, (64, 196, 255), aura_1)
    glow2 = _radial_glow(size, (size * 0.62, size * 0.55), size * 0.60, (124, 77, 255), aura_2)
    bg = Image.alpha_composite(bg, glow1)
    bg = Image.alpha_composite(bg, glow2)

    # Hafif vignette
    vign = _radial_glow(size, (size * 0.5, size * 0.55), size * 0.95, (0, 0, 0), vignette)
    bg = Image.alpha_composite(bg, vign)

    img = Image.alpha_composite(img, bg)

    # Ön plan çizimleri
    draw = ImageDraw.Draw(img)

    # Kulaklık (özgün, sade)
    stroke = int(round(size * 0.03))
    white = (245, 245, 245, 235)
    soft_white = (245, 245, 245, 180)

    cx, cy = size * 0.5, size * 0.44
    arc_r = size * 0.22
    arc_box = [cx - arc_r, cy - arc_r, cx + arc_r, cy + arc_r]

    # Üst bant: arkada renk efekti, üstte beyaz çizgi
    arc_rain = _draw_rainbow_arc_layer(
        size,
        (arc_box[0], arc_box[1], arc_box[2], arc_box[3]),
        start=200,
        end=340,
        width=max(1, int(round(stroke * 1.05))),
        alpha=int(hp_arc_alpha),
        steps=56,
        blur_radius=max(1, size * 0.0025),
    )
    img = Image.alpha_composite(img, arc_rain)
    draw = ImageDraw.Draw(img)
    draw.arc(arc_box, start=200, end=340, fill=soft_white, width=stroke)

    # Ear pads
    pad_w = size * 0.11
    pad_h = size * 0.18
    pad_r = int(round(size * 0.05))

    left_pad = [cx - arc_r - pad_w * 0.25, cy + arc_r * 0.05, cx - arc_r + pad_w * 0.75, cy + arc_r * 0.05 + pad_h]
    right_pad = [cx + arc_r - pad_w * 0.75, cy + arc_r * 0.05, cx + arc_r + pad_w * 0.25, cy + arc_r * 0.05 + pad_h]

    draw.rounded_rectangle(left_pad, radius=pad_r, fill=(255, 255, 255, 30), outline=white, width=int(round(stroke * 0.55)))
    draw.rounded_rectangle(right_pad, radius=pad_r, fill=(255, 255, 255, 30), outline=white, width=int(round(stroke * 0.55)))

    # Kulaklık içi renk efekti (pad iç yüzey): maskeli gökkuşağı + hafif blur
    def _pad_inner_effect(pad_box: list[float]) -> None:
        x0, y0, x1, y1 = pad_box
        w = int(round(x1 - x0))
        h = int(round(y1 - y0))
        if w <= 2 or h <= 2:
            return
        inset = max(2, int(round(size * 0.010)))
        # İçte biraz daha dar bir alan (pedin "iç" kısmı gibi)
        inner_w = max(2, w)
        inner_h = max(2, h)
        mask = _rounded_rect_mask(inner_w, inner_h, radius=int(pad_r), inset=inset)

        grad = _linear_rainbow(inner_w, inner_h, alpha=int(hp_pad_alpha), horizontal=True)
        grad = grad.filter(ImageFilter.GaussianBlur(radius=max(1, int(round(size * 0.003)))))

        layer = Image.new("RGBA", (inner_w, inner_h), (0, 0, 0, 0))
        layer.paste(grad, (0, 0), mask)

        # Hafif merkez glow ile daha "içten" görünüm
        glow = _radial_glow(
            max(inner_w, inner_h),
            (max(inner_w, inner_h) * 0.52, max(inner_w, inner_h) * 0.58),
            max(inner_w, inner_h) * 0.55,
            (64, 196, 255),
            0.22 if variant != "clean" else 0.14,
        )
        glow = glow.resize((inner_w, inner_h), resample=Image.Resampling.BILINEAR)
        layer = Image.alpha_composite(layer, glow)

        img.alpha_composite(layer, (int(round(x0)), int(round(y0))))

    _pad_inner_effect(left_pad)
    _pad_inner_effect(right_pad)

    # İçte "A" imzası: küçükte okunabilir, varyasyonla daha belirgin
    a_w = size * 0.06
    a_h = size * 0.10
    a_top = (cx, cy - a_h * 0.42)
    a_left = (cx - a_w, cy + a_h * 0.45)
    a_right = (cx + a_w, cy + a_h * 0.45)
    a_cross_y = cy + a_h * 0.06
    a_cross_l = (cx - a_w * 0.50, a_cross_y)
    a_cross_r = (cx + a_w * 0.50, a_cross_y)

    a_width = int(round(stroke * 0.55 * a_boost))
    a_cross_width = int(round(stroke * 0.45 * a_boost))

    # Hafif glow
    if a_glow > 0.0:
        glow_layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        gd = ImageDraw.Draw(glow_layer)
        gcol = (64, 196, 255, int(round(255 * a_glow)))
        gd.line([a_left, a_top, a_right], fill=gcol, width=max(1, int(round(a_width * 1.35))), joint="curve")
        gd.line([a_cross_l, a_cross_r], fill=gcol, width=max(1, int(round(a_cross_width * 1.35))))
        glow_layer = glow_layer.filter(ImageFilter.GaussianBlur(radius=max(1, int(round(size * 0.008)))) )
        img = Image.alpha_composite(img, glow_layer)
        draw = ImageDraw.Draw(img)

    draw.line([a_left, a_top, a_right], fill=white, width=max(1, a_width), joint="curve")
    draw.line([a_cross_l, a_cross_r], fill=white, width=max(1, a_cross_width))

    # Spektrum barları (gökkuşağı; Aurivo görselleştirme hissi)
    base_y = size * 0.72
    bar_w = size * 0.03
    gap = size * 0.013
    start_x = cx - (bar_count * bar_w + (bar_count - 1) * gap) / 2

    if bar_count == 9:
        heights = [0.20, 0.34, 0.52, 0.74, 0.92, 0.72, 0.50, 0.34, 0.22]
    else:
        heights = [0.18, 0.30, 0.42, 0.55, 0.72, 0.88, 0.70, 0.54, 0.40, 0.28, 0.20]
    bar_r = int(round(size * 0.02))
    for i in range(bar_count):
        h = size * 0.22 * heights[i]
        x0 = start_x + i * (bar_w + gap)
        y0 = base_y - h
        x1 = x0 + bar_w
        y1 = base_y
        col = _rainbow(i / max(1, bar_count - 1))
        draw.rounded_rectangle([x0, y0, x1, y1], radius=bar_r, fill=(col[0], col[1], col[2], int(bar_alpha)))

    # İnce alt çizgi (ikonun tabanı)
    draw.line([size * 0.22, base_y + size * 0.03, size * 0.78, base_y + size * 0.03], fill=(255, 255, 255, 55), width=int(round(size * 0.006)))

    return img


def _make_preview_sheet(icons: Tuple[Tuple[str, Image.Image], ...], tile: int = 256) -> Image.Image:
    """Basit yan-yana önizleme (dosyaları açıp seçmek kolay olsun)."""
    pad = 28
    w = pad + len(icons) * (tile + pad)
    h = tile + pad * 2 + 36
    sheet = Image.new("RGBA", (w, h), (16, 16, 18, 255))
    draw = ImageDraw.Draw(sheet)
    try:
        font = ImageFont.load_default()
    except Exception:
        font = None

    x = pad
    y = pad
    for name, im in icons:
        thumb = im.resize((tile, tile), resample=Image.Resampling.LANCZOS)
        sheet.alpha_composite(thumb, (x, y))
        if font is not None:
            draw.text((x, y + tile + 10), name, fill=(230, 230, 230, 235), font=font)
        x += tile + pad
    return sheet


def save_png(img: Image.Image, path: str, size: int) -> None:
    out = img.resize((size, size), resample=Image.Resampling.LANCZOS)
    out.save(path, format="PNG", optimize=True)


def save_ico(img: Image.Image, path: str, sizes: Iterable[int]) -> None:
    base = img
    ico_sizes = [(s, s) for s in sizes]
    base.save(path, format="ICO", sizes=ico_sizes)


def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)

    # Varsayılan (packaging'in kullandığı dosya adları)
    master = make_master_icon(1024, variant="default")
    master_path = os.path.join(OUT_DIR, "aurivo_app_1024.png")
    master.save(master_path, format="PNG", optimize=True)

    save_png(master, os.path.join(OUT_DIR, "aurivo.png"), 256)
    save_png(master, os.path.join(OUT_DIR, "aurivo_512.png"), 512)
    save_png(master, os.path.join(OUT_DIR, "aurivo_128.png"), 128)
    save_png(master, os.path.join(OUT_DIR, "aurivo_64.png"), 64)
    save_png(master, os.path.join(OUT_DIR, "aurivo_48.png"), 48)
    save_png(master, os.path.join(OUT_DIR, "aurivo_32.png"), 32)
    save_png(master, os.path.join(OUT_DIR, "aurivo_24.png"), 24)
    save_png(master, os.path.join(OUT_DIR, "aurivo_16.png"), 16)
    save_ico(master, os.path.join(OUT_DIR, "aurivo.ico"), sizes=[16, 24, 32, 48, 64, 128, 256])

    # Alternatifler (seçenek göstermek için)
    alt_bold = make_master_icon(1024, variant="bold_a")
    alt_clean = make_master_icon(1024, variant="clean")

    alt_bold_1024 = os.path.join(OUT_DIR, "aurivo_alt_boldA_1024.png")
    alt_clean_1024 = os.path.join(OUT_DIR, "aurivo_alt_clean_1024.png")
    alt_bold.save(alt_bold_1024, format="PNG", optimize=True)
    alt_clean.save(alt_clean_1024, format="PNG", optimize=True)

    save_png(alt_bold, os.path.join(OUT_DIR, "aurivo_alt_boldA.png"), 256)
    save_png(alt_clean, os.path.join(OUT_DIR, "aurivo_alt_clean.png"), 256)

    # Önizleme sheet
    sheet = _make_preview_sheet(
        (
            ("default", master),
            ("bold A", alt_bold),
            ("clean", alt_clean),
        ),
        tile=256,
    )
    sheet_path = os.path.join(OUT_DIR, "aurivo_icon_variants_preview.png")
    sheet.save(sheet_path, format="PNG", optimize=True)

    print("✓ Icon outputs written to:")
    print(" -", master_path)
    print(" -", os.path.join(OUT_DIR, "aurivo.png"))
    print(" -", os.path.join(OUT_DIR, "aurivo.ico"))
    print(" -", alt_bold_1024)
    print(" -", alt_clean_1024)
    print(" -", sheet_path)


if __name__ == "__main__":
    main()
