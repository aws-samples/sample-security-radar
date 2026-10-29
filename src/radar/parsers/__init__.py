"""Parsers: source body → list[RawItem]. Pure functions, no network (the collector fetches)."""

from __future__ import annotations

import html
import json
import re
from collections.abc import Callable

import feedparser
from bs4 import BeautifulSoup

from radar import keys, signals, timeutil
from radar.model import RawItem

Parser = Callable[[str, str], list[RawItem]]


def _text(fragment: str) -> tuple[str, list[str]]:
    """HTML fragment → (plain text, hrefs). Data comes from the public internet: we never keep markup."""
    if not fragment:
        return "", []
    if "<" not in fragment:
        return html.unescape(fragment).strip(), []
    soup = BeautifulSoup(fragment, "html.parser")
    links = [a["href"] for a in soup.find_all("a", href=True) if a["href"].startswith("http")]
    return re.sub(r"\s+", " ", soup.get_text(" ")).strip(), links


def feed(body: str, source_id: str) -> list[RawItem]:
    parsed = feedparser.parse(body)
    out: list[RawItem] = []
    for e in parsed.entries:
        content = (e.get("content") or [{}])[0].get("value") or e.get("summary", "")
        text, links = _text(content)
        published = timeutil.parse(e.get("published") or e.get("updated"))
        out.append(RawItem(source_id=source_id, url=e.get("link", ""), title=_text(e.get("title", ""))[0],
                           text=text, published_at=published, guid=e.get("id") or e.get("link"),
                           author=e.get("author"), links=links))
    return out


def kev(body: str, source_id: str) -> list[RawItem]:
    out = []
    for v in json.loads(body)["vulnerabilities"]:
        cve = v["cveID"]
        title = f"{cve} {v.get('vendorProject', '')} {v.get('product', '')}: {v.get('vulnerabilityName', '')}".strip()
        out.append(RawItem(
            source_id=source_id, url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}",
            title=title, text=v.get("shortDescription", ""), published_at=timeutil.parse(v.get("dateAdded")),
            guid=cve, extra={"cves": [cve], "kev": True, "kev_date_added": v.get("dateAdded"),
                             "ransomware": v.get("knownRansomwareCampaignUse") == "Known", "cwes": list(v.get("cwes") or []),
                             "entity": v.get("vendorProject"), "product": v.get("product")}))
    return out


def defillama(body: str, source_id: str) -> list[RawItem]:
    out = []
    for h in json.loads(body):
        d = timeutil.parse(h["date"])
        chains = [c for c in (h.get("chain") or []) if c]
        amount = h.get("amount")
        title = f"{h['name']} — {h.get('technique') or h.get('classification') or 'hack'}"
        # DeFiLlama has no event id; (name, date) is its natural key. A rename creates a new item, which the
        # entity key then merges back into the same event.
        out.append(RawItem(
            source_id=source_id, url=f"https://defillama.com/hacks#{h['name']}", title=title,
            text=f"{h['name']} {h.get('classification', '')} {h.get('technique', '')} on {', '.join(chains)}",
            published_at=d, guid=f"{h['name']}|{h['date']}",
            extra={"entity": h["name"], "amount_usd": float(amount) if amount is not None else None,
                   "returned_usd": h.get("returnedFunds"), "chains": chains,
                   "classification": h.get("classification"), "technique": h.get("technique"),
                   "target_type": h.get("targetType")}))
    return out


def slowmist(body: str, source_id: str) -> list[RawItem]:
    soup = BeautifulSoup(body, "html.parser")
    out = []
    for li in soup.select("li"):
        t, h3 = li.find("span", class_="time"), li.find("h3")
        if not t or not h3:
            continue
        target = h3.get_text(" ", strip=True).removeprefix("Hacked target:").strip()
        fields = {}
        for em in li.find_all("em"):
            label = em.get_text(strip=True).rstrip(":").strip().lower()
            val = (em.next_sibling or "")
            fields[label] = val.strip() if isinstance(val, str) else ""
        ref = li.find("a", href=True)
        ref_url = ref["href"] if ref else ""
        date = t.get_text(strip=True)
        out.append(RawItem(
            source_id=source_id, url=f"https://hacked.slowmist.io/#{date}-{target}",
            title=f"{target} — {fields.get('attack method') or 'hacked'}",
            text=fields.get("description of the event", ""), published_at=timeutil.parse(date),
            guid=f"{target}|{date}", links=[ref_url] if ref_url else [],
            extra={"entity": target, "amount_usd": signals.parse_amount(fields.get("amount of loss")),
                   "attack_method": fields.get("attack method")}))
    return out


_DHL_HEAD = re.compile(r"^### (\d{8}) (.+?) - ([^\n]*)")
_DHL_LOST = re.compile(r"^### Lost\s*:?\s*(.*)$", re.MULTILINE)
_DHL_SOL = re.compile(r"\]\((?:\./)?(src/test/[^)]+\.sol)\)")


def defihacklabs(body: str, source_id: str) -> list[RawItem]:
    """README → entries. Attack tx/attacker live in the PoC header; the collector fetches the .sol and
    calls `defihacklabs_poc` to enrich. Entry shapes vary (blank lines, '### Lost  ', no Lost line at all),
    so each entry is parsed from its own chunk with optional parts."""
    out = []
    for chunk in re.split(r"(?=^### \d{8} )", body, flags=re.MULTILINE):
        m = _DHL_HEAD.match(chunk)
        if not m:
            continue
        day, name, desc = m.group(1), m.group(2).strip(), m.group(3).strip()
        lost_m, sol_m = _DHL_LOST.search(chunk), _DHL_SOL.search(chunk)
        lost = lost_m.group(1).strip() if lost_m else ""
        sol = sol_m.group(1) if sol_m else None
        out.append(RawItem(
            source_id=source_id,
            url=f"https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/{sol}" if sol
            else f"https://github.com/SunWeb3Sec/DeFiHackLabs#{day}-{name}",
            title=f"{name} — {desc[:120]}", text=f"{desc}\nLost: {lost}", published_at=timeutil.parse(day),
            guid=sol or f"{day}|{name}|{keys.short_hash(desc)}",  # same day+name can be two incidents
            extra={"entity": name, "lost_text": lost or None, "poc": True,
                   "sol_url": f"https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/{sol}" if sol else None}))
    return out


def defihacklabs_poc(sol: str) -> dict[str, object]:
    """Parse the `// @KeyInfo` header of a DeFiHackLabs PoC file."""
    head = "\n".join(line for line in sol.splitlines()[:40] if line.startswith("//"))
    attackers = re.findall(r"//\s*Attacker\s*:\s*(https?://\S+)", head)
    total = re.search(r"Total Lost\s*:\s*(.+)", head)
    return {"attack_tx": keys.tx_refs(head), "attacker_urls": attackers,
            "total_lost_text": total.group(1).strip() if total else None}


def twitterapi(body: str, source_id: str) -> list[RawItem]:
    data = json.loads(body)
    out = []
    for t in data.get("tweets") or []:
        author = (t.get("author") or {}).get("userName", "")
        text = t.get("text") or ""
        links = [u.get("expanded_url") for u in (t.get("entities") or {}).get("urls", []) if u.get("expanded_url")]
        rt = t.get("retweeted_tweet") or None
        qt = t.get("quoted_tweet") or None
        for ref in (rt, qt):
            if isinstance(ref, dict) and ref.get("url"):
                links.append(ref["url"])
        if isinstance(qt, dict):
            text += "\n> " + (qt.get("text") or "")
        out.append(RawItem(
            source_id=source_id, url=t.get("url") or f"https://x.com/{author}/status/{t['id']}",
            title=re.sub(r"\s+", " ", text)[:140], text=text, published_at=timeutil.parse(t.get("createdAt")),
            guid=str(t["id"]), author=author, links=links,
            extra={"x_status": str(t["id"]), "retweet": bool(rt)}))
    return out


PARSERS: dict[str, Parser] = {
    "feed": feed, "kev": kev, "defillama": defillama, "slowmist": slowmist,
    "defihacklabs": defihacklabs, "twitterapi": twitterapi,
}
