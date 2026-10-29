"""Build the README gallery from full-page screenshots: vertical strips, each slowly scrolling through one page.

  uv run python scripts/build_gallery.py build/gallery docs/gallery

Outputs docs/gallery/gallery.svg (animated, self-contained — images inlined as data URIs, so it animates inside a
GitHub README <img>; prefers-reduced-motion ⇒ static) and docs/gallery/gallery.png (static fallback, top of each page).
Driven by scripts/gallery.sh, which takes the screenshots from the live site."""

from __future__ import annotations

import base64
import io
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

STRIPS = [  # (file stem, label, sub-label)
    ("01-home", "态势首页", "L0 headline · 漏斗 · NOW"),
    ("03-continuum", "AWS Continuum 融入", "覆盖 · 账本 · 能力链路"),
    ("04-env-php2shell", "在你的环境中 · PHP2Shell", "定位到行 · EXPLOITABLE · 补丁"),
    ("05-env-alpscon", "在你的环境中 · AlpsCon", "Web3 IOC · 白名单命中"),
    ("07-web3", "Web3 被盗", "DeFiLlama · 慢雾 · DeFiHackLabs"),
]
W, H = 1600, 900                  # canvas
TOP, PAD, GAP = 96, 40, 18        # header band, side padding, gap between strips
SW = (W - 2 * PAD - GAP * (len(STRIPS) - 1)) // len(STRIPS)   # strip width
SH = H - TOP - 92                 # visible strip height (label band below)
RENDER_W = SW * 2                 # 2x for crisp HiDPI
MAX_SRC_H = 4200                  # cap very long pages: the strip scrolls through the top ~4–5 viewports
CROP_X = (214, 1440)              # drop the left nav so the strip shows the page's own content at a legible scale
FONT = "'Space Grotesk','Noto Sans SC','PingFang SC','Microsoft YaHei',sans-serif"


def strip_image(path: Path) -> tuple[bytes, int]:
    im = Image.open(path).convert("RGB")
    im = im.crop((CROP_X[0], 0, min(im.width, CROP_X[1]), min(im.height, MAX_SRC_H)))
    scale = RENDER_W / im.width
    im = im.resize((RENDER_W, int(im.height * scale)), Image.LANCZOS)
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=72, optimize=True, progressive=True)
    return buf.getvalue(), im.height // 2   # displayed height at 1x


def svg(strips: list[tuple[str, str, bytes, int]]) -> str:
    parts = [(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
             f'role="img" aria-label="Security Radar UI gallery">'),
             "<defs>",
             ('<linearGradient id="g-bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0B1220"/>'
             '<stop offset="1" stop-color="#151036"/></linearGradient>'),
             ('<linearGradient id="g-edge" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#22D3EE"/>'
             '<stop offset="0.5" stop-color="#8B5CF6"/><stop offset="1" stop-color="#F472B6"/></linearGradient>'),
             ('<linearGradient id="g-fade" x1="0" y1="0" x2="0" y2="1"><stop offset="0.82" stop-color="#0B1220" stop-opacity="0"/>'
             '<stop offset="1" stop-color="#0B1220" stop-opacity="0.85"/></linearGradient>')]
    css = [f"text{{font-family:{FONT}}}", ".t{fill:#F1F5F9;font-size:30px;font-weight:700}",
           ".s{fill:#94A3B8;font-size:15px}", ".l{fill:#E2E8F0;font-size:16px;font-weight:600}",
           ".m{fill:#64748B;font-size:12px}",
           "@keyframes sheen{0%{opacity:.35}50%{opacity:1}100%{opacity:.35}}",
           ".edge{animation:sheen 6s ease-in-out infinite}"]
    for i, (_stem, _label, _jpg, h) in enumerate(strips):
        travel = max(0, h - SH)
        dur = 26 + 4 * i                      # staggered so strips never move in lockstep
        css.append(f"@keyframes sc{i}{{0%,8%{{transform:translateY(0)}}46%,54%{{transform:translateY(-{travel}px)}}"
                   f"92%,100%{{transform:translateY(0)}}}}")
        css.append(f".sc{i}{{animation:sc{i} {dur}s ease-in-out {-(i * 3)}s infinite}}")
        parts.append(f'<clipPath id="c{i}"><rect x="0" y="0" width="{SW}" height="{SH}" rx="14"/></clipPath>')
    css.append("@media (prefers-reduced-motion: reduce){[class^=sc],.edge{animation:none!important}}")
    parts.append("</defs>")
    parts.append(f"<style>{''.join(css)}</style>")
    parts.append(f'<rect width="{W}" height="{H}" fill="url(#g-bg)"/>')
    parts.append(f'<text x="{PAD}" y="52" class="t">Security Radar · UI 画廊</text>')
    parts.append(f'<text x="{PAD}" y="78" class="s">线上真实数据 · 探测 → 触发 AWS Security Agent / AWS Continuum → 证实与补丁回流</text>')
    for i, (stem, label, jpg, h) in enumerate(strips):
        x = PAD + i * (SW + GAP)
        sub = next(s[2] for s in STRIPS if s[0] == stem)
        data = base64.b64encode(jpg).decode()
        parts.append(f'<g transform="translate({x},{TOP})">')
        parts.append(f'<rect x="-2" y="-2" width="{SW + 4}" height="{SH + 4}" rx="16" fill="none" stroke="url(#g-edge)" '
                     f'stroke-width="2" class="edge" style="animation-delay:{-i}s"/>')
        parts.append(f'<g clip-path="url(#c{i})"><rect width="{SW}" height="{SH}" fill="#0F172A"/>'
                     f'<g class="sc{i}"><image href="data:image/jpeg;base64,{data}" width="{SW}" height="{h}"/></g>'
                     f'<rect width="{SW}" height="{SH}" fill="url(#g-fade)"/></g>')
        parts.append(f'<text x="2" y="{SH + 32}" class="l">{label}</text>')
        parts.append(f'<text x="2" y="{SH + 54}" class="m">{sub}</text>')
        parts.append("</g>")
    parts.append("</svg>")
    return "\n".join(parts)


def png(strips: list[tuple[str, str, bytes, int]], out: Path) -> None:
    canvas = Image.new("RGB", (W * 2, H * 2), (11, 18, 32))
    d = ImageDraw.Draw(canvas)
    try:
        font_t = ImageFont.truetype("/System/Library/Fonts/PingFang.ttc", 60)
        font_l = ImageFont.truetype("/System/Library/Fonts/PingFang.ttc", 32)
    except OSError:
        font_t = font_l = ImageFont.load_default()
    d.text((PAD * 2, 50), "Security Radar · UI 画廊", fill=(241, 245, 249), font=font_t)
    for i, (_stem, label, jpg, _h) in enumerate(strips):
        x = (PAD + i * (SW + GAP)) * 2
        im = Image.open(io.BytesIO(jpg)).crop((0, 0, RENDER_W, SH * 2))
        mask = Image.new("L", im.size, 0)
        ImageDraw.Draw(mask).rounded_rectangle((0, 0, im.width, im.height), radius=28, fill=255)
        canvas.paste(im, (x, TOP * 2), mask)
        d.text((x + 4, (TOP + SH) * 2 + 30), label, fill=(226, 232, 240), font=font_l)
    # 1x, 256-colour: the static fallback only needs to look right in a README, not weigh 3 MB
    canvas.resize((W, H), Image.LANCZOS).convert("P", palette=Image.ADAPTIVE, colors=256).save(out, optimize=True)


def main() -> None:
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    dst.mkdir(parents=True, exist_ok=True)
    strips = []
    for stem, label, _sub in STRIPS:
        jpg, h = strip_image(src / f"{stem}.png")
        strips.append((stem, label, jpg, h))
    (dst / "gallery.svg").write_text(svg(strips))
    png(strips, dst / "gallery.png")
    print(f"gallery.svg {(dst / 'gallery.svg').stat().st_size // 1024} KB · gallery.png {(dst / 'gallery.png').stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
