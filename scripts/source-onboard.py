"""Source onboarding harness: may a candidate feed join the registry? Decided by code, from the radar's own egress.

  AWS_PROFILE=<profile> uv run python scripts/source-onboard.py --urls candidates.txt [--json build/onboard.json]
  uv run python scripts/source-onboard.py --replay build/onboard.json        # re-judge stored bodies, no network

A status code is not enough (2026-11-09: 10 of 92 candidate feeds answered 200 with 1–3 KB — challenge pages and
empty shells). A throwaway Lambda (same runtime / role / region as the Process station, deleted after use — the
laptop never fetches third-party feeds) GETs each URL with the radar's headers and returns the body; locally the
REAL parser (radar.parsers.feed) reads it and `verdict` decides: ok / stale / empty / blocked / failed.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import importlib.util
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from radar import keys, parsers, signals


class Limits:
    STALE_DAYS = 30              # newest entry older than this ⇒ the feed is dead or moved
    MIN_ITEMS = 1
    BATCH = 6                    # URLs per Lambda invoke: gzip'd bodies must fit the 6 MB response payload
    MAX_BODY = 2_000_000         # bytes kept per feed (before gzip)


HANDLER = r'''
import base64, gzip, socket, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor
_gai = socket.getaddrinfo   # IPv4 first, as the radar's fetch does in Lambda (no IPv6 egress; radar.fetch)
socket.getaddrinfo = lambda *a, **k: [r for r in _gai(*a, **k) if r[0] == socket.AF_INET] or _gai(*a, **k)
UA = {"User-Agent": "security-radar/0.1 (+https://github.com/; contact: owner)", "Accept-Encoding": "gzip"}
def get(url, cap):
    t0 = time.time()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=20) as r:
            raw = r.read(cap * 4)
            if r.headers.get("Content-Encoding") == "gzip":
                raw = gzip.decompress(raw)
            return {"url": url, "status": r.status, "final_url": r.geturl(), "ctype": r.headers.get("Content-Type"),
                    "seconds": round(time.time() - t0, 2),
                    "body": base64.b64encode(gzip.compress(raw[:cap])).decode()}
    except urllib.error.HTTPError as e:
        return {"url": url, "status": e.code, "seconds": round(time.time() - t0, 2), "server": e.headers.get("Server")}
    except Exception as e:
        return {"url": url, "exception": str(e)[:160], "seconds": round(time.time() - t0, 2)}
def handler(event, _ctx):
    with ThreadPoolExecutor(8) as ex:
        return list(ex.map(lambda u: get(u, event["cap"]), event["urls"]))
'''


def _probe_module():
    spec = importlib.util.spec_from_file_location("probe", ROOT / "scripts" / "probe-from-lambda.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def fetch_from_lambda(urls: list[str]) -> list[dict[str, Any]]:
    probe = _probe_module()
    probe.HANDLER = HANDLER                       # same throwaway-function lifecycle, different handler
    out: list[dict[str, Any]] = []

    def run(invoke):
        for i in range(0, len(urls), Limits.BATCH):
            out.extend(invoke({"urls": urls[i:i + Limits.BATCH], "cap": Limits.MAX_BODY}))
        return 0
    probe._with_function(run)
    return out


def body_of(r: dict[str, Any]) -> str:
    return gzip.decompress(base64.b64decode(r["body"])).decode("utf-8", "replace") if r.get("body") else ""


def judge(r: dict[str, Any], now: datetime, parser: str = "feed") -> dict[str, Any]:
    """Parse with the production parser named for the candidate (default: feed) and grade it. A parser the registry
    does not have yet grades "unparsed" — the body is kept in --json as the fixture for writing one."""
    if "exception" in r or r.get("status") != 200:
        return {"url": r["url"], "verdict": verdict(r.get("status"), 0, None, now), "status": r.get("status"),
                "error": r.get("exception")}
    if parser not in parsers.PARSERS:
        return {"url": r["url"], "verdict": "unparsed", "status": 200, "parser": parser}
    try:
        raws = parsers.PARSERS[parser](body_of(r), "onboard")
    except (ValueError, KeyError, TypeError) as e:     # a JSON shape the parser does not know
        return {"url": r["url"], "verdict": "empty", "status": 200, "parser": parser, "error": str(e)[:120]}
    dates = [x.published_at for x in raws if x.published_at]
    newest = max(dates) if dates else None
    sec = sum(1 for x in raws if signals.security_event(x.title) or signals.web3_incident(x.title)
              or keys.cves(f"{x.title}\n{x.text}"))
    return {"url": r["url"], "verdict": verdict(200, len(raws), newest, now), "status": 200, "items": len(raws),
            "newest": newest.isoformat() if newest else None, "security_items": sec,
            "final_url": r.get("final_url"), "sample": [x.title[:90] for x in raws[:3]]}


def verdict(status: int | None, items: int, newest: datetime | None, now: datetime) -> str:
    """ok: parses to entries and published within STALE_DAYS. A feed with entries but no dates is ok (some vendor
    feeds omit them) — the collector dates such items at capture."""
    if status != 200:
        return "blocked" if status in (401, 403, 429, 451) else "failed"
    if items < Limits.MIN_ITEMS:
        return "empty"
    if newest is not None and now - newest > timedelta(days=Limits.STALE_DAYS):
        return "stale"
    return "ok"


def main() -> int:
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--urls", type=Path, help="one candidate per line: `URL` or `<parser> URL`")
    src.add_argument("--replay", type=Path, help="re-judge a stored --json run, no network")
    ap.add_argument("--json", type=Path, default=ROOT / "build" / "source-onboard.json")
    args = ap.parse_args()
    now = datetime.now(UTC)
    if args.replay:
        fetched = json.loads(args.replay.read_text())["fetched"]
    else:
        lines = [ln.split("#", 1)[0].split() if " #" in ln else ln.split()     # `<parser> <url>  # comment`
                 for ln in args.urls.read_text().splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
        lines = [ln for ln in lines if ln]
        wanted = {ln[-1]: (ln[0] if len(ln) > 1 else "feed") for ln in lines}
        fetched = fetch_from_lambda(list(wanted))
        for r in fetched:
            r["parser"] = wanted[r["url"]]
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps({"at": now.isoformat(), "fetched": fetched}))
    rows = [judge(r, now, r.get("parser", "feed")) for r in fetched]
    for r in sorted(rows, key=lambda r: (r["verdict"], r["url"])):
        print(f"{r['verdict']:8} {r.get('items', '-')!s:>4} items  sec {r.get('security_items', '-')!s:>3}  "
              f"newest {str(r.get('newest') or '-')[:10]}  {r['url']}  {r.get('error') or ''}")
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print(json.dumps(counts))
    (args.json.with_suffix(".verdicts.json")).write_text(json.dumps(rows, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
