"""Product registry for the respond station (D-class: deterministic, no LLM).

A product entry answers three questions for a radar event, all by code:
  1. does the event concern this product?            → `title` regex over the event title + entities
  2. which versions does the evidence call fixed / affected?  → versions after a product name, classified
     by the words in front of them ("update to", "fixed in" ⇒ fixed; "ran on", "affected" ⇒ affected)
  3. where does a target code base pin this product?  → `locators` (file glob + line regex → version)

Adding a product = one registry entry + one real-evidence test; never a new code path (context-budget §8)."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Locator:
    glob: str           # matched against the file's basename (fnmatch)
    pattern: str        # regex with one group = the version
    kind: str           # what this pin is (runtime image, CI image, platform config …) — shown in the UI


@dataclass(frozen=True)
class Product:
    product_id: str
    name: str                           # display + requirement text
    title: str                          # regex: event concerns this product
    version_names: tuple[str, ...]      # how evidence spells the product right before a version
    locators: tuple[Locator, ...] = field(default=())


_IMG = r"(?:[\w.-]+(?::\d+)?/)*"  # optional registry/namespace prefix of an image reference

PRODUCTS: tuple[Product, ...] = (
    Product("php", "PHP", r"\bPHP\b", ("PHP", "php"), (
        Locator("Dockerfile*", rf"^\s*FROM\s+{_IMG}php:(\d+\.\d+(?:\.\d+)?)", "runtime image"),
        Locator("*.yml", rf"image:\s*[\"']?{_IMG}php:(\d+\.\d+(?:\.\d+)?)", "CI image"),
        Locator("*.yaml", rf"image:\s*[\"']?{_IMG}php:(\d+\.\d+(?:\.\d+)?)", "CI image"),
        Locator("composer.json", r"\"php\"\s*:\s*\"(\d+\.\d+\.\d+)\"", "composer platform"),
        Locator(".tool-versions", r"^php\s+(\d+\.\d+\.\d+)", "tool-versions"),
        Locator("Dockerfile*", rf"^\s*FROM\s+{_IMG}wordpress:[\w.]*-php(\d+\.\d+)", "WordPress image PHP branch"),
    )),
    Product("nodejs", "Node.js", r"\bNode(?:\.js|JS)\b|\bNode2Shell\b", ("Node.js", "NodeJS", "node"), (
        Locator("Dockerfile*", rf"^\s*FROM\s+{_IMG}node:(\d+(?:\.\d+){{0,2}})", "runtime image"),
        Locator("*.yml", rf"image:\s*[\"']?{_IMG}node:(\d+(?:\.\d+){{0,2}})", "CI image"),
        Locator("*.yaml", rf"image:\s*[\"']?{_IMG}node:(\d+(?:\.\d+){{0,2}})", "CI image"),
        Locator(".nvmrc", r"^v?(\d+(?:\.\d+){0,2})\s*$", "nvmrc"),
        Locator(".node-version", r"^v?(\d+(?:\.\d+){0,2})\s*$", "node-version"),
        Locator("*.py", r"Runtime\.NODEJS_(\d+)_X", "Lambda runtime"),
    )),
    Product("python", "Python", r"\b(?:C?Python)\b", ("Python", "CPython"), (
        Locator("Dockerfile*", rf"^\s*FROM\s+{_IMG}python:(\d+\.\d+(?:\.\d+)?)", "runtime image"),
        Locator("*.yml", rf"image:\s*[\"']?{_IMG}python:(\d+\.\d+(?:\.\d+)?)", "CI image"),
        Locator("*.yaml", rf"image:\s*[\"']?{_IMG}python:(\d+\.\d+(?:\.\d+)?)", "CI image"),
        Locator(".python-version", r"^(\d+\.\d+(?:\.\d+)?)\s*$", "python-version"),
        Locator("*.py", r"Runtime\.PYTHON_(\d+_\d+)", "Lambda runtime"),
        Locator("pyproject.toml", r"requires-python\s*=\s*\"[>=~^]*(\d+\.\d+)", "requires-python"),
    )),
    # Registered so the station can answer "not in our code" deterministically; no locators needed until
    # a target uses them (then add locators + a test, nothing else).
    Product("openssl", "OpenSSL", r"\bOpenSSL\b", ("OpenSSL",)),
    Product("nginx", "nginx", r"\bnginx\b", ("nginx",)),
    Product("wordpress", "WordPress", r"\bWordPress\b", ("WordPress",), (
        Locator("Dockerfile*", rf"^\s*FROM\s+{_IMG}wordpress:(\d+\.\d+(?:\.\d+)?)", "runtime image"),
    )),
    Product("apache-struts", "Apache Struts", r"\bStruts\b", ("Struts",)),
    Product("strapi", "Strapi", r"\bStrapi\b", ("Strapi",)),
    Product("magento", "Adobe Commerce / Magento", r"\bMagento\b|\bAdobe Commerce\b", ("Magento",)),
)
BY_PRODUCT = {p.product_id: p for p in PRODUCTS}

_VERSION = re.compile(r"\d+\.\d+\.\d+")
# "PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35" / "PHP 8.5.12、8.4.27" — one product mention, several versions
_LIST = r"(\d+\.\d+\.\d+(?:\s*(?:,|、|，|and|or|和|及)\s*(?:{n}\s+)?\d+\.\d+\.\d+)*)"
_FIX_WORDS = re.compile(r"update to|upgrade to|updated to|fixes are in|fixed in|patched in|addressed in|"
                        r"released|patches? (?:in|for)|已发布|修复|升级到|更新到", re.IGNORECASE)
_AFFECT_WORDS = re.compile(r"\bran\b|running|\bon the official\b|\bon (?:an? )?official\b|affected|vulnerable|"
                           r"\bbuild of\b|受影响|运行", re.IGNORECASE)
WINDOW = 80  # characters before the version list that decide fixed vs affected


def match(title: str, entities: list[str]) -> Product | None:
    text = " ".join([title, *entities])
    return next((p for p in PRODUCTS if re.search(p.title, text)), None)


def versions(product: Product, texts: list[str]) -> tuple[list[str], list[str]]:
    """(fixed, affected) versions stated in evidence, newest first. Unclassifiable mentions are dropped:
    a version we cannot place is not a fact we can act on."""
    fixed: set[str] = set()
    affected: set[str] = set()
    names = "|".join(re.escape(n) for n in product.version_names)
    rx = re.compile(rf"(?:{names})\s+(?:v(?:ersion)?\s*)?" + _LIST.format(n=f"(?:{names})"))
    for t in texts:
        for m in rx.finditer(t):
            before = t[max(0, m.start() - WINDOW): m.start()]
            vs = _VERSION.findall(m.group(1))
            # the nearest cue word wins (a sentence can say "ran on X … fixed in Y")
            f, a = _last(_FIX_WORDS, before), _last(_AFFECT_WORDS, before)
            if f > a:
                fixed.update(vs)
            elif a > f:
                affected.update(vs)
    key = lambda v: tuple(int(x) for x in v.split("."))
    return sorted(fixed, key=key, reverse=True), sorted(affected - fixed, key=key, reverse=True)


def _last(rx: re.Pattern[str], text: str) -> int:
    pos = -1
    for m in rx.finditer(text):
        pos = m.end()
    return pos


@dataclass(frozen=True)
class Pin:
    product_id: str
    version: str
    file: str
    line: int
    kind: str


def inventory(files: dict[str, str]) -> list[Pin]:
    """Every registered product pin in a code base ({path: text}). Lambda runtime enums use '_' (3_12)."""
    out: list[Pin] = []
    for path in sorted(files):
        base = path.rsplit("/", 1)[-1]
        for p in PRODUCTS:
            for loc in p.locators:
                if not fnmatch.fnmatch(base, loc.glob):
                    continue
                for n, line in enumerate(files[path].splitlines(), 1):
                    m = re.search(loc.pattern, line)
                    if m:
                        out.append(Pin(p.product_id, m.group(1).replace("_", "."), path, n, loc.kind))
    return out


def _parts(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def verdict(pin_version: str, fixed: list[str], affected: list[str]) -> tuple[str, str | None]:
    """('affected', fixed_for_branch) | ('fixed', …) | ('unknown', None).
    Affected = same major.minor branch as a fixed release and lower, or exactly a version the evidence
    names as affected. A partial pin ('24', '8.3') cannot be compared ⇒ unknown (the AI review decides)."""
    v = _parts(pin_version)
    if len(v) < 3:
        return "unknown", None
    if pin_version in affected:
        return "affected", next((f for f in fixed if _parts(f)[:2] == v[:2]), None)
    for f in fixed:
        if _parts(f)[:2] == v[:2]:
            return ("affected" if v < _parts(f) else "fixed"), f
    return "unknown", None
