"""Parsers: source body → list[RawItem]. Pure functions, no network (the collector fetches)."""

from __future__ import annotations

import html
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import feedparser
from bs4 import BeautifulSoup

from radar import keys, signals, timeutil
from radar.model import RawItem
from radar.parsers import exchanges as _exchanges

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


def feed(body: str, source_id: str, naive_tz: timezone | None = None) -> list[RawItem]:
    """RSS / Atom / RDF. `naive_tz`: the zone of timestamps that carry none (feed_cst) — otherwise they read as UTC."""
    parsed = feedparser.parse(body)
    out: list[RawItem] = []
    for e in parsed.entries:
        content = (e.get("content") or [{}])[0].get("value") or e.get("summary", "")
        text, links = _text(content)
        stamp = e.get("published") or e.get("updated")
        published = timeutil.parse(stamp)
        if naive_tz is not None and published is not None and isinstance(stamp, str) and _NAIVE.match(stamp.strip()):
            published = published.replace(tzinfo=naive_tz).astimezone(UTC)
        title = _text(e.get("title", ""))[0]
        outlet = ((e.get("source") or {}).get("title") or "").strip()
        if outlet and title.endswith(f" - {outlet}"):
            # Google News appends 「 - Outlet」: the outlet is the reporter, not part of the story (it glued unrelated
            # stories through tok:rfi / 币界网, live 2026-11-10)
            title = title[: -len(outlet) - 3].rstrip()
        out.append(RawItem(source_id=source_id, url=e.get("link", ""), title=title,
                           text=text, published_at=published, guid=e.get("id") or e.get("link"),
                           author=e.get("author"), links=links))
    return out


# 洞见 doonsec writes 「2026-11-09T13:15:34」 — China time without a zone (docs/research/18 §A.3): read as UTC it is
# 8 h in the future. Defined here once, chosen per source by parser name.
_NAIVE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?$")
CST = timezone(timedelta(hours=8))


def feed_cst(body: str, source_id: str) -> list[RawItem]:
    return feed(body, source_id, naive_tz=CST)


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
    rows = json.loads(body)
    # (name, date) is not unique: DeFiLlama lists Gamma 2021-12-21 twice ($4.5M arithmetic error, $8.2M reentrancy),
    # OcelotDex and Merlin too. One guid for two hacks made the item flip between the two amounts on every run — 1,634
    # amount_change entries in ~3 weeks, the event row at 396 KB of DynamoDB's 400 KB (live 2026-11-10). Duplicates get
    # a stable suffix: sorted by (technique, amount), the first keeps the plain guid (existing items stay theirs).
    dup: dict[str, list[dict[str, Any]]] = {}
    for h in rows:
        dup.setdefault(f"{h['name']}|{h['date']}", []).append(h)
    suffix = {id(h): (f"#{k}" if k else "") for g in dup.values()
              for k, h in enumerate(sorted(g, key=lambda h: (str(h.get("technique") or ""), float(h.get("amount") or 0))))}
    for h in rows:
        d = timeutil.parse(h["date"])
        chains = [c for c in (h.get("chain") or []) if c]
        amount = h.get("amount")
        title = f"{h['name']} — {h.get('technique') or h.get('classification') or 'hack'}"
        # DeFiLlama has no event id; (name, date) is its natural key. A rename creates a new item, which the
        # entity key then merges back into the same event.
        out.append(RawItem(
            source_id=source_id, url=f"https://defillama.com/hacks#{h['name']}{suffix[id(h)]}", title=title,
            text=f"{h['name']} {h.get('classification', '')} {h.get('technique', '')} on {', '.join(chains)}",
            published_at=d, guid=f"{h['name']}|{h['date']}{suffix[id(h)]}",
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


_MD_ESC = re.compile(r"\\([\\`*_{}\[\]()#+\-.!|>~])")
_X_STATUS_URL = re.compile(r"https://x\.com/(\w{1,15})/status/(\d{5,25})")
_POST_HEAD = re.compile(r"^### \d+\. Post\s*$", re.MULTILINE)


def x_profile_markdown(md: str) -> list[dict[str, Any]]:
    """firecrawl's markdown of an x.com profile → tweets shaped like the X data source's (id, url, text, createdAt,
    author.userName, entities.urls, retweeted_tweet), so the twitterapi parser below needs no second path. Blocks
    are `### N. Post` / `Posted:` / `URL: [..](..)` / `> ` body lines; a block whose URL is not a status link is dropped
    (the format is firecrawl's own post-processing and drifts — ISO vs RFC 2822 dates seen the same day)."""
    out = []
    for block in _POST_HEAD.split(md)[1:]:
        posted = re.search(r"^Posted:\s*(.+)$", block, re.MULTILINE)
        link = re.search(r"^URL:\s*\[[^\]]*\]\(([^)]+)\)", block, re.MULTILINE)
        m = _X_STATUS_URL.fullmatch(link.group(1)) if link else None
        if not (posted and m):
            continue
        body = [ln[2:] if ln.startswith("> ") else ln[1:] for ln in block.splitlines() if ln.startswith(">")]
        while body and body[-1].strip() in ("", "---"):
            body.pop()
        text = _MD_ESC.sub(r"\1", "\n".join(body)).strip()
        t: dict[str, Any] = {"id": m.group(2), "url": m.group(0), "text": text,
                             "createdAt": _MD_ESC.sub(r"\1", posted.group(1)).strip(), "author": {"userName": m.group(1)},
                             "entities": {"urls": [{"expanded_url": u} for u in re.findall(r"https?://[^\s)\]]+", text)]}}
        if text.startswith("RT @"):
            t["retweeted_tweet"] = {"url": None}   # only marks it a retweet; the original's URL is not in the snapshot
        out.append(t)
    return out


def twitterapi(body: str, source_id: str) -> list[RawItem]:
    data = json.loads(body)
    via = data.get("via", "twitterapi")
    if "profiles" in data:   # the firecrawl fallback (fetch.firecrawl_x_profiles)
        tweets = [t for md in data["profiles"].values() for t in x_profile_markdown(md)]
        if not tweets and any(md.strip() for md in data["profiles"].values()):
            # a login wall / format change parses to nothing — that is breakage, not "no new posts"
            raise ValueError(f"parse_empty: 0 posts in {len(data['profiles'])} profile snapshots")
        data = {"tweets": tweets}
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
            extra={"x_status": str(t["id"]), "retweet": bool(rt), **({"via": via} if via != "twitterapi" else {})}))
    return out


def binance_cms(body: str, source_id: str) -> list[RawItem]:
    """Binance announcement CMS (bapi …/cms/article/list/query): an exchange's own notices — the first-hand loss, freeze
    and withdrawal statements (M4 D5). Title only: the list endpoint carries no body; the page URL is the identity."""
    out = []
    for cat in (json.loads(body).get("data") or {}).get("catalogs") or []:
        for a in cat.get("articles") or []:
            code, title = a.get("code"), (a.get("title") or "").strip()
            if not code or not title:
                continue
            out.append(RawItem(source_id=source_id, url=f"https://www.binance.com/en/support/announcement/detail/{code}",
                               title=title, text=title, published_at=timeutil.parse((a.get("releaseDate") or 0) / 1000),
                               guid=code))
    return out


# CISA's CSAF provider (www.cisa.gov/sites/default/files/csaf/provider-metadata.json, role csaf_trusted_provider) lists
# ROLIE feeds on GitHub. Why (live 2026-11-04→): CISA's CDN answers the radar's AWS egress with 403 on every dynamic page,
# RSS included (cybersecurity-advisories/all.xml, ics-advisories.xml), while static files (KEV) pass — so the advisories
# come from the CSAF feeds instead (OT = ICS advisories, IT = VA-* coordinated disclosures).
_CISA_WEB = {"ICSA": "ics-advisories", "ICSMA": "ics-medical-advisories"}


def rolie(body: str, source_id: str) -> list[RawItem]:
    """Every entry of a CSAF ROLIE feed. An update (「Update B」) is a report of its own: guid = id@updated. An ICS
    advisory keeps the URL the CISA RSS gave it, so a CSAF report meets the event an RSS report opened."""
    out = []
    for e in json.loads(body)["feed"]["entry"]:
        aid = e["id"]
        href = next((ln.get("href") for ln in e.get("link") or [] if ln.get("href")), None) or (e.get("content") or {}).get("src")
        prefix = aid.split("-")[0].upper()
        url = f"https://www.cisa.gov/news-events/{_CISA_WEB[prefix]}/{aid.lower()}" if prefix in _CISA_WEB else href
        when = e.get("updated") or e.get("published")
        out.append(RawItem(source_id=source_id, url=url, title=f"{aid} {e.get('title') or ''}".strip(), text="",
                           published_at=timeutil.parse(when), guid=f"{aid}@{when}", author=None, links=[],
                           extra={"csaf_url": href, "advisory_id": aid}))
    return out


def csaf_doc(body: str) -> dict[str, object]:
    """CVEs, highest CVSS v3/v4 base score, vendors and the summary of one CSAF 2.0 advisory."""
    doc = json.loads(body)
    vulns = doc.get("vulnerabilities") or []
    cves = sorted({v["cve"] for v in vulns if v.get("cve")})
    scores = [s.get(k, {}).get("baseScore") for v in vulns for s in v.get("scores") or [] for k in ("cvss_v4", "cvss_v3")]
    vendors = [b["name"] for b in (doc.get("product_tree") or {}).get("branches") or []
               if b.get("category") == "vendor" and b.get("name")]
    summary = next((n.get("text") for n in (doc.get("document") or {}).get("notes") or [] if n.get("category") == "summary"), "")
    text = " ".join(x for x in (summary, ("Vendor: " + ", ".join(vendors)) if vendors else "", " ".join(cves)) if x)
    return {"cves": cves, "cvss": max((x for x in scores if x is not None), default=None), "vendors": vendors, "text": text}



def telegram(body: str, source_id: str) -> list[RawItem]:
    """A public channel's web preview t.me/s/<name> (docs/research/18 §B.2): one post per
    div.tgme_widget_message[data-post="<channel>/<id>"], time[datetime] in UTC, text in .tgme_widget_message_text.
    No bot, no MTProto. A page without posts parses to [] — the collector reports parse_empty (a dead channel falls
    back to the contact page with HTTP 200, which must not read as "no news")."""
    soup = BeautifulSoup(body, "html.parser")
    out = []
    for m in soup.select("div.tgme_widget_message[data-post]"):
        post = m.get("data-post", "")
        when = m.select_one("a.tgme_widget_message_date time[datetime]")
        link = m.select_one("a.tgme_widget_message_date")
        node = m.select_one("div.tgme_widget_message_text")
        text = node.get_text("\n", strip=True) if node else ""
        if not post or not text:
            continue              # a photo-only post carries no reportable text
        links = [a["href"] for a in node.select("a[href]")] if node else []
        # alert channels open with 「🚨」 or a hashtag line: the title is the first line that says something
        lines = [ln for ln in text.split("\n") if len(re.findall(r"[A-Za-z0-9\u4e00-\u9fff]", ln)) >= 6]
        title = (lines[0] if lines else text.split("\n", 1)[0])[:160]
        out.append(RawItem(source_id=source_id, url=(link.get("href") if link else f"https://t.me/{post}"), title=title,
                           text=text[:4000], published_at=timeutil.parse(when["datetime"]) if when else None,
                           guid=post, links=links))
    return out


def cvelist_delta(body: str, source_id: str) -> list[RawItem]:
    """CVE Program's cvelistV5 delta.json (or deltaLog.json, a list of deltas): every *new* CVE record of the window.
    Title / text / CVSS / vendor come from the record itself (collect fetches extra.record_url, cve_record below).
    An empty window is normal — it parses to [] without being an error (collect.EMPTY_OK)."""
    data = json.loads(body)
    out = []
    for delta in data if isinstance(data, list) else [data]:
        for n in delta.get("new") or []:
            cve = n.get("cveId")
            if not cve or not n.get("githubLink"):
                continue
            out.append(RawItem(source_id=source_id, url=n.get("cveOrgLink") or f"https://www.cve.org/CVERecord?id={cve}",
                               title=cve, text=cve, published_at=timeutil.parse(n.get("dateUpdated")), guid=cve,
                               extra={"cves": [cve], "record_url": n["githubLink"], "fetch_time": delta.get("fetchTime")}))
    return out


def cve_record(body: str) -> dict[str, Any]:
    """One CVE JSON 5 record: what the report says (CNA title, first description), the CNA's or an ADP's CVSS
    (cvemeta.parse — the same rule as the disclosure ledger) and the first affected vendor / product."""
    from radar import cvemeta
    rec = json.loads(body)
    cna = (rec.get("containers") or {}).get("cna") or {}
    desc = next((d.get("value", "") for d in cna.get("descriptions") or [] if d.get("lang", "en").startswith("en")), "")
    aff = (cna.get("affected") or [{}])[0]
    meta = cvemeta.parse(rec)
    title = (cna.get("title") or desc.split(". ")[0] or "")[:200]
    return {"title": title, "text": desc[:4000], "cvss": meta["cvss"], "severity": meta["severity"],
            "vendor": aff.get("vendor") if aff.get("vendor") not in (None, "n/a") else None,
            "product": aff.get("product") if aff.get("product") not in (None, "n/a") else None,
            "published": meta["published"], "assigner": meta["assigner"]}

def msrc(body: str, source_id: str) -> list[RawItem]:
    """Microsoft Security Update Guide (sug/v2.0 OData, R2.7): one row per CVE, newest revision first. `exploited` is
    Microsoft's own "Exploitation Detected" — carried as extra.vendor_exploited (pipeline: exploited = yes), not left to
    the text rules. The RSS feed was not used: it is the whole quarter (3.3 MB, 5,792 entries measured 2026-11-15)."""
    out = []
    for v in json.loads(body).get("value") or []:
        cve = (v.get("cveNumber") or "").strip()
        if not cve:
            continue
        exploited = v.get("exploited") == "Yes"
        facts = [x for x in (v.get("severity"), v.get("impact"), v.get("tag")) if x]
        if exploited:
            facts.append("exploitation detected by Microsoft")
        if v.get("publiclyDisclosed") == "Yes":
            facts.append("publicly disclosed")
        try:
            cvss = float(v.get("baseScore") or "")
        except ValueError:
            cvss = None
        out.append(RawItem(
            source_id=source_id, url=f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}",
            title=f"{cve} {v.get('cveTitle') or ''}".strip(), text=" · ".join(facts),
            published_at=timeutil.parse(v.get("releaseDate")), guid=cve,
            extra={"cves": [cve], "vendor_exploited": exploited, "cvss": cvss, "entity": "Microsoft",
                   "product": v.get("tag"), "revised_at": v.get("latestRevisionDate")}))
    return out


def broadcom(body: str, source_id: str) -> list[RawItem]:
    """Broadcom support portal advisory list (VMSA, R2.7): {"data": {"list": [...]}} newest first. `published` is a
    day ("28 October 2026", no zone ⇒ UTC midnight); `updated` marks a revision (VMSA-…-0006.1), which changes the
    title, so the content hash re-hands it over."""
    out = []
    for v in (json.loads(body).get("data") or {}).get("list") or []:
        doc = (v.get("documentId") or "").strip()
        if not doc:
            continue
        cves = re.findall(r"CVE-\d{4}-\d{4,}", v.get("affectedCve") or "")
        try:
            day = datetime.strptime((v.get("published") or "").strip(), "%d %B %Y").replace(tzinfo=UTC)
        except ValueError:
            day = None
        facts = [x for x in (v.get("severity"), v.get("supportProducts"), v.get("status")) if x]
        out.append(RawItem(
            source_id=source_id, url=v.get("notificationUrl") or "", title=(v.get("title") or doc).strip(),
            text=" · ".join(facts), published_at=day, guid=doc,
            extra={"cves": cves, "entity": "VMware", "product": v.get("supportProducts"), "revised_at": v.get("updated")}))
    return out


PARSERS: dict[str, Parser] = {
    "feed": feed, "kev": kev, "defillama": defillama, "slowmist": slowmist,
    "defihacklabs": defihacklabs, "twitterapi": twitterapi, "binance_cms": binance_cms, "rolie": rolie,
    "zendesk": _exchanges.zendesk, "telegram": telegram, "feed_cst": feed_cst, "cvelist_delta": cvelist_delta, "msrc": msrc, "broadcom": broadcom, **{k: _exchanges.by_spec(k) for k in _exchanges.SPECS},
}
