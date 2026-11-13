"""Pull (P3): static JSON Feed 1.1 + Atom documents under data/feeds/, written by the publish station.

No new surface: they are objects in the site bucket behind the site's existing CloudFront Basic Auth, like every other
data/ document (research/action/03 §4 — a public feed is an exposure decision, not made here). Feed readers that cannot
send Basic Auth (cloud readers) cannot subscribe; scripts, curl and self-hosted readers can.

FEEDS is the one table of feeds; data/feeds/index.json is generated from it. A feed's filters are subscription filters
(radar.notify.FILTER_FIELDS) and are matched by the same pure function, so 「p0 feed」 and a P0 subscription can never
disagree. Items come from radar.notify.view over the PUBLIC listing row — nothing internal is an input.
"""

from __future__ import annotations

import json
import re

# builds XML only; nothing in this module parses XML
import xml.etree.ElementTree as ET  # nosec B405 # nosemgrep
from datetime import datetime
from typing import Any

from radar import notify, timeutil
from radar.limits import Limits
from radar.model import SITE_SCHEMA_VERSION

# name → (title, filters). Order = order in index.json.
FEEDS: dict[str, tuple[str, dict[str, Any]]] = {
    "all": ("全部事件", {}),
    "p0": ("P0 事件", {"severity": ["P0"]}),
    "web3": ("Web3 事件", {"domain": ["web3"]}),
    "vuln": ("漏洞事件", {"domain": ["vuln"]}),
    "exchanges": ("涉及交易所（radar.wallets 登记的交易所）", {"exchanges": list(notify.EXCHANGES)}),
    "has-waf-pack": ("已有 WAF 规则包", {"has_waf_pack": True}),
}
JSON_FEED_VERSION = "https://jsonfeed.org/version/1.1"
ATOM_NS = "http://www.w3.org/2005/Atom"
RADAR_NS = "https://security-radar/ns/feed"
JSON_TYPE = "application/feed+json"
ATOM_TYPE = "application/atom+xml"


def _link(site_url: str, event_id: str) -> str:
    return f"{site_url.rstrip('/')}/#/events/{event_id}"


def _radar(v: dict[str, Any]) -> dict[str, Any]:
    return {k: v[k] for k in ("severity", "level", "domain", "chains", "cves", "products", "exchanges",
                              "has_waf_pack", "has_verdict", "impact")}


def json_feed(name: str, items: list[dict[str, Any]], now_iso: str, site_url: str) -> dict[str, Any]:
    title, filters = FEEDS[name]
    base = site_url.rstrip("/")
    return {"version": JSON_FEED_VERSION, "title": f"Security Radar · {title}", "home_page_url": f"{base}/",
            "feed_url": f"{base}/data/feeds/{name}.json",
            "_radar": {"schema_version": SITE_SCHEMA_VERSION, "feed": name, "filters": filters, "generated_at": now_iso},
            "items": [{"id": v["event_id"], "url": _link(site_url, v["event_id"]), "title": f"[{v['severity']}] {v['title']}",
                       "content_text": v["summary"] or v["level_reason"] or v["title"],
                       "date_published": v["first_seen"], "date_modified": v["last_updated"],
                       "tags": [v["severity"], v["domain"], *v["cves"]], "_radar": _radar(v)} for v in items]}


# Everything outside the XML 1.0 Char production (C0 controls but tab/newline/CR, lone surrogates, U+FFFE/U+FFFF).
# ElementTree escapes < & " but writes these as they are, and ONE of them makes the whole document not well-formed:
# titles and summaries are collected third-party text (a \x01 or an ANSI \x1b[31m in a feed title), and nothing
# at ingest strips them. Readers then fail silently on all.atom. JSON escapes them, so only the Atom needs this.
_NOT_XML_CHAR = re.compile("[^\t\n\r\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")


def xml_text(s: str) -> str:
    """Drop characters XML 1.0 cannot carry (escaping cannot help: &#1; is not allowed either)."""
    return _NOT_XML_CHAR.sub("", s)


def atom(name: str, items: list[dict[str, Any]], now_iso: str, site_url: str) -> bytes:
    """Atom 1.0 (RFC 4287). Ids are tag: URIs on the event id — stable across runs and title fixes."""
    title, _ = FEEDS[name]
    ET.register_namespace("", ATOM_NS)
    ET.register_namespace("radar", RADAR_NS)

    def el(parent: ET.Element, tag: str, text: str | None = None, **attrs: str) -> ET.Element:
        e = ET.SubElement(parent, f"{{{ATOM_NS}}}{tag}", {k: xml_text(v) for k, v in attrs.items()})
        if text is not None:
            e.text = xml_text(text)
        return e
    feed = ET.Element(f"{{{ATOM_NS}}}feed")
    el(feed, "id", f"tag:security-radar,2026:feed:{name}")
    el(feed, "title", f"Security Radar · {title}")
    el(feed, "updated", items[0]["last_updated"] if items else now_iso)
    el(feed, "link", rel="self", href=f"{site_url.rstrip('/')}/data/feeds/{name}.atom")
    el(feed, "link", rel="alternate", href=f"{site_url.rstrip('/')}/")
    ET.SubElement(feed, f"{{{RADAR_NS}}}schema_version").text = SITE_SCHEMA_VERSION
    for v in items:
        e = el(feed, "entry")
        el(e, "id", f"tag:security-radar,2026:event:{v['event_id']}")
        el(e, "title", f"[{v['severity']}] {v['title']}")
        el(e, "updated", v["last_updated"])
        el(e, "published", v["first_seen"])
        el(e, "link", rel="alternate", href=_link(site_url, v["event_id"]))
        el(e, "summary", v["summary"] or v["level_reason"] or v["title"])
        for t in (v["severity"], v["domain"], *v["cves"]):
            el(e, "category", term=t)
    return b'<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(feed, encoding="utf-8")


def documents(rows: list[dict[str, Any]], mitigation: dict[str, Any], now: datetime, site_url: str,
              skip: set[str] | None = None) -> dict[str, tuple[bytes, str]]:
    """{path under data/: (body, content type)}. rows = events.json rows (publish._summary); mitigation =
    __mitigate__.events; skip = events whose page this run deferred (never link to a page that is not written)."""
    now_iso = timeutil.iso(now)
    vs = [notify.view(r, bool((mitigation.get(r["event_id"]) or {}).get("plans")))
          for r in rows if r["event_id"] not in (skip or set())]
    vs.sort(key=lambda v: (v["last_updated"] or "", v["event_id"]), reverse=True)
    out: dict[str, tuple[bytes, str]] = {}
    index = []
    for name, (title, filters) in FEEDS.items():
        items = [v for v in vs if notify.matches(filters, v)][: Limits.FEED_MAX_ITEMS]
        out[f"feeds/{name}.json"] = (json.dumps(json_feed(name, items, now_iso, site_url), ensure_ascii=False).encode(),
                                     JSON_TYPE)
        out[f"feeds/{name}.atom"] = (atom(name, items, now_iso, site_url), ATOM_TYPE)
        index.append({"name": name, "title": title, "filters": filters, "items": len(items),
                      "json": f"feeds/{name}.json", "atom": f"feeds/{name}.atom"})
    out["feeds/index.json"] = (json.dumps(index_doc(index, now_iso), ensure_ascii=False).encode(), "application/json")
    return out


def index_doc(feeds: list[dict[str, Any]], now_iso: str) -> dict[str, Any]:
    return {"kind": "feeds", "schema_version": SITE_SCHEMA_VERSION, "generated_at": now_iso, "feeds": feeds}
