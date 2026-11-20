"""Trim the empty bottom of section screenshots (scripts/live-shots.sh): rows that are one flat colour, like the page
background a capped section shot can end in (live 2026-11-18: 430 px of black under the PHP2Shell 「在你的环境中」 shot).

  uv run python scripts/trim_shots.py docs/screenshots/live-env-php2shell-dark.png …
"""
import sys

from PIL import Image

PAD = 16          # keep this many background rows under the content
TOLERANCE = 6     # per-channel difference still counted as "the same colour"


def content_bottom(im: Image.Image) -> int:
    px, (w, h) = im.convert("RGB").load(), im.size
    bg = px[w // 2, h - 1]
    for y in range(h - 1, -1, -1):
        for x in range(0, w, 4):
            p = px[x, y]
            if any(abs(p[i] - bg[i]) > TOLERANCE for i in range(3)):
                return y + 1
    return h


def main(paths: list[str]) -> int:
    for p in paths:
        im = Image.open(p)
        bottom = min(im.size[1], content_bottom(im) + PAD)
        if bottom < im.size[1]:
            im.crop((0, 0, im.size[0], bottom)).save(p)
        print(f"{p}: {im.size[1]} → {bottom}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
