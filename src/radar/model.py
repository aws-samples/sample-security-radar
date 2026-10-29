"""Core data model. Items are what sources said; Events are what we believe happened.

Every derived field on Event (level, severity, exploitation, amounts) is recomputed by code from its
items — never written by an LLM and never edited in place by hand."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Literal

from radar import timeutil

Domain = Literal["vuln", "incident", "web3"]
Tier = Literal["T1", "T2", "T3"]
Level = Literal["V0", "V1", "V2", "V3", "V4", "X"]
Severity = Literal["P0", "P1", "P2"]
Exploitation = Literal["none", "poc", "reported", "confirmed"]
Exploited = Literal["yes", "no", "unclear"]

LEVEL_ORDER: dict[str, int] = {"X": -1, "V0": 0, "V1": 1, "V2": 2, "V3": 3, "V4": 4}
SEVERITY_ORDER: dict[str, int] = {"P2": 0, "P1": 1, "P0": 2}
EXPLOITATION_ORDER: dict[str, int] = {"none": 0, "poc": 1, "reported": 2, "confirmed": 3}


@dataclass
class RawItem:
    """Parser output: one entry as the source published it. `extra` carries structured fields the
    parser could read reliably (amount, attack tx, KEV fields…); free text stays in `text`."""

    source_id: str
    url: str
    title: str
    text: str
    published_at: datetime | None
    guid: str | None = None
    author: str | None = None
    links: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["published_at"] = timeutil.iso(self.published_at) if self.published_at else None
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RawItem:
        return cls(**{**d, "published_at": timeutil.parse(d.get("published_at"))})


@dataclass
class Item:
    item_id: str
    source_id: str
    tier: Tier
    org: str                      # publishing organisation; same org ⇒ never independent
    domain: Domain
    url: str
    canonical_url: str
    title: str
    text: str
    published_at: str             # ISO UTC (fetched_at when the source gave none)
    fetched_at: str
    content_hash: str
    keys: list[str]               # blocking keys, e.g. "cve:CVE-2026-1234", "tx:0x…", "ent:bitget"
    links: list[str]              # canonical outbound links (echo detection)
    entity: str | None
    eventful: bool                # False ⇒ stored for context, never opens an event on its own
    signals: dict[str, Any]       # exploited, kev, poc, amount_usd, cvss
    extra: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Item:
        return cls(**d)


@dataclass
class Event:
    event_id: str
    domain: Domain
    title: str
    first_seen: str
    last_updated: str
    item_ids: list[str]
    keys: list[str]
    level: Level = "V0"
    level_reason: str = ""
    severity: Severity = "P2"
    exploitation: Exploitation = "none"
    independent_sources: int = 0
    first_report_source: str = ""
    amount_history: list[dict[str, Any]] = field(default_factory=list)
    amount_usd_latest: float | None = None
    amount_disputed: bool = False
    timeline: list[dict[str, Any]] = field(default_factory=list)
    entities: list[str] = field(default_factory=list)
    chains: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    tx: list[dict[str, Any]] = field(default_factory=list)
    summary: str | None = None
    # publication time of the evidence that last raised level (≤V3) or exploitation; drives P0 freshness
    escalated_at: str = ""
    analysis: dict[str, Any] | None = None   # analyst station output (radar.analyst), incl. input_hash

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Event:
        return cls(**d)
