"""P2 · WAF rule pack — one customer-owned AWS WAF RuleGroup per event, decided by code (docs/research/action/01-waf.md §4).

A pack = {managed, custom, templates, rejected}:
  managed    AWS managed rule groups that cover the event (mitigate.waf_plans — the same CVE / product / CWE tiers the
             station applies — without the located-target precondition: a reader's own stack is the target)
  custom     rules built from VERBATIM features of a pinned nuclei template (radar.pocs) or of an evidence sentence, by
             one registry of extractors (EXTRACTORS / EVIDENCE_EXTRACTORS: a new feature = one row)
  templates  rate / origin-lockdown / IP-set templates, triggered by registered evidence wording (TEMPLATE_TRIGGERS),
             always heuristic, never passed off as evidence rules
  rejected   every candidate that did not make it, with the reason (machine code + words) — 「生成失败：原因」 is shown,
             never silently dropped (degradation-and-guards §1)

Hard rules (PackRule refuses to exist otherwise — construction raises):
  * at least one source quote {repo, sha(40 hex), path, line, token} or {url, sentence, token}, the token verbatim
  * no {{variable}} of a template ever becomes a match string (only the registered ORIGIN_SECRET placeholder, in the
    origin template); no generic header (Host, User-Agent, Accept …) is ever a matched field
  * action Count — Block is a reader's decision after watching the counts
And one gate (radar.wafmatch): a rule enters `custom` / `templates` only if its positive samples match and its negative
samples do not; `unchecked` (SqliMatch / rate: not reproducible offline) is shown as such, never as pass.
The radar never writes a customer resource: a pack is text to copy (packrender), the only AWS call is the read-only
CheckCapacity (mitigate station)."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import timedelta
from typing import Any

from radar import mitigate, pocs, timeutil
from radar.limits import Limits
from radar.pocs import HELPER, VAR, Template, TemplateRequest
from radar.wafmatch import Request, gate

KEY = "__rule_pack__#"          # + event_id → the pack row (single writer: the mitigate station)
CONFIDENCE = ("exact", "heuristic")
KINDS = ("byte", "regex", "size", "and", "sqli", "ipset", "rate", "origin_lockdown")
ORIGIN_SECRET_PLACEHOLDER = "{{ORIGIN_SECRET}}"     # the one placeholder a match string may hold (origin template only)  # noqa: S105 — a template placeholder, not a secret
IPSET_ARN_PLACEHOLDER = "{{IPSET_ARN}}"
ORIGIN_HEADER = "x-origin-verify"
# headers every client sends — never a rule's field (08 §2.1). Content-Type is generic too: as the only condition it
# would block a media type.
CLIENT_HEADERS = frozenset({"host", "user-agent", "accept", "accept-encoding", "accept-language", "connection",
                            "content-length", "content-type", "cache-control", "pragma", "cookie", "origin", "referer",
                            "upgrade-insecure-requests", "te", "dnt", "x-requested-with", "authorization"})
# headers a proxy / CDN / load balancer adds to (nearly) every request: behind CloudFront → ALB, x-forwarded-proto
# is `https` on all traffic — an article naming one must never become a rule (review of p1/rulepack: two such
# `exact` rules passed the gate because the benign corpus carried no proxy header; BENIGN now does too).
PROXY_HEADERS = frozenset({"x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-forwarded-port", "x-real-ip",
                           "forwarded", "via", "x-amzn-trace-id", "x-amz-cf-id"})
GENERIC_HEADERS = CLIENT_HEADERS | PROXY_HEADERS
SAMPLE_OAST = "oast.example.invalid"
SAMPLE_VALUE = "radarsample"


def key(event_id: str) -> str:
    return KEY + event_id


# ---------------------------------------------------------------- model
@dataclass(frozen=True)
class Quote:
    token: str
    repo: str | None = None
    sha: str | None = None
    path: str | None = None
    line: int | None = None
    url: str | None = None
    sentence: str | None = None
    item_id: str | None = None                 # evidence: the item whose evidence_text(item) holds the token …
    span: tuple[int, int] | None = None        # … at [start, end) — 01-waf §4: `text[span[0]:span[1]] == value`

    def __post_init__(self) -> None:
        if len(self.token.strip()) < Limits.RULEPACK_MIN_TOKEN:
            raise ValueError(f"quote token {self.token!r} shorter than {Limits.RULEPACK_MIN_TOKEN}")
        if self.repo is not None:
            if not (self.sha and pocs.SHA.fullmatch(self.sha) and self.path and self.line and self.line > 0):
                raise ValueError(f"a template quote needs repo + a 40-hex commit SHA + path + line, got {self.sha!r}")
            if not pocs.safe_path(self.path):   # the path becomes a fetch URL (--check) and a link (page / markdown)
                raise ValueError(f"template quote path {str(self.path)[:80]!r} outside the template-path grammar")
        elif not (self.url and self.sentence and self.token in self.sentence):
            raise ValueError("an evidence quote needs url + a sentence that contains the token verbatim")
        elif not (self.item_id and self.span and len(self.span) == 2 and 0 <= self.span[0]
                  and self.span[1] - self.span[0] == len(self.token)):
            # without a source position --check could only re-test token-in-sentence: the tautology above
            raise ValueError(f"an evidence quote needs item_id + span of the token's length, got {self.item_id!r} {self.span!r}")

    def as_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if v is not None}
        if self.span is not None:
            d["span"] = list(self.span)
        return d


def evidence_text(item: Any) -> str:
    """THE text an evidence quote's span indexes into — the extractors read it, --check re-reads it from the store."""
    return f"{item.title}. {item.text}"


def verify_quote(q: dict[str, Any], text: str) -> bool:
    """--check, on the source re-read: a template quote's token is verbatim on its line of the text at the pinned SHA;
    an evidence quote's token is exactly text[span[0]:span[1]] of evidence_text(item) and its sentence is in that text."""
    if q.get("repo"):
        lines = text.split("\n")
        n = int(q.get("line") or 0)
        return 0 < n <= len(lines) and q["token"] in lines[n - 1]
    span = q.get("span") or []
    if len(span) != 2:
        return False
    sentence = q.get("sentence") or "\0"
    if text[span[0]:span[1]] == q["token"] and sentence in text:
        return True
    # a pack built before the age stamp was stripped quotes "| 42 minutes ago"; the stored text now reads another age
    sentence, text = timeutil.strip_relative_age(sentence), timeutil.strip_relative_age(text)
    # a source that revises its entry moves the quote (live 2026-11-19: cvefeed, CVE-2026-132560 — the token 7 chars
    # further on, the deploy check went red): still verbatim when the quoted sentence is in the text and holds the token
    return q["token"] in sentence and sentence in text


def _walk(stmt: dict[str, Any]):
    kind, s = next(iter(stmt.items()))
    yield kind, s
    for sub in s.get("Statements") or []:
        yield from _walk(sub)
    for k in ("Statement", "ScopeDownStatement"):
        if isinstance(s.get(k), dict):
            yield from _walk(s[k])


@dataclass(frozen=True)
class PackRule:
    rule_id: str
    kind: str
    extractor: str
    statement: dict[str, Any]                  # the AWS WAF Statement — the one source every rendering wraps
    source_quotes: tuple[Quote, ...]
    confidence: str
    false_positive_note: str
    positives: tuple[Request, ...]
    negatives: tuple[Request, ...]
    cve: str | None = None
    action: str = "Count"
    ip_set: dict[str, Any] | None = None       # {"addresses": [cidr …], "version": IPV4} for kind ipset
    verified: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in KINDS or self.confidence not in CONFIDENCE:
            raise ValueError(f"kind {self.kind!r} / confidence {self.confidence!r} not registered")
        if not self.source_quotes:
            raise ValueError(f"{self.rule_id}: a rule without a source quote does not exist")
        if self.action != "Count":
            raise ValueError(f"{self.rule_id}: a pack rule is Count — Block is the reader's decision")
        if not self.false_positive_note.strip():
            raise ValueError(f"{self.rule_id}: false_positive_note is required")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", self.rule_id):
            raise ValueError(f"rule id {self.rule_id!r} is not a valid WAF rule name")
        for kind, s in _walk(self.statement):
            for k in ("SearchString", "RegexString"):
                if k not in s:
                    continue
                v = s[k]
                if VAR.search(v) and not (self.kind == "origin_lockdown" and v == ORIGIN_SECRET_PLACEHOLDER):
                    raise ValueError(f"{self.rule_id}: template variable in a match string {v!r}")
                if len(v.strip()) < Limits.RULEPACK_MIN_TOKEN and kind == "ByteMatchStatement":
                    raise ValueError(f"{self.rule_id}: match string {v!r} shorter than {Limits.RULEPACK_MIN_TOKEN}")
            hdr = ((s.get("FieldToMatch") or {}).get("SingleHeader") or {}).get("Name")
            if hdr and hdr.lower() in GENERIC_HEADERS:
                raise ValueError(f"{self.rule_id}: generic header {hdr!r} is never a rule's field")

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"rule_id": self.rule_id, "kind": self.kind, "extractor": self.extractor, "cve": self.cve,
                             "statement": self.statement, "source_quotes": [q.as_dict() for q in self.source_quotes],
                             "confidence": self.confidence, "false_positive_note": self.false_positive_note,
                             "action": self.action, "verified": self.verified,
                             "samples": {"positive": [r.as_dict() for r in self.positives],
                                         "negative": [r.as_dict() for r in self.negatives]}}
        if self.ip_set is not None:
            d["ip_set"] = self.ip_set
        return d


@dataclass(frozen=True)
class Candidate:
    """What an extractor proposes; the builder turns it into a PackRule (validation) and gates it (wafmatch)."""
    kind: str
    statement: dict[str, Any]
    quotes: tuple[Quote, ...]
    positives: tuple[Request, ...]
    negatives: tuple[Request, ...]
    confidence: str
    fp_note: str


# ---------------------------------------------------------------- statement builders
def _tts(*types: str) -> list[dict[str, Any]]:
    return [{"Priority": i, "Type": t} for i, t in enumerate(types or ("NONE",))]


def byte(ftm: dict[str, Any], search: str, positional: str, *types: str) -> dict[str, Any]:
    return {"ByteMatchStatement": {"SearchString": search, "PositionalConstraint": positional, "FieldToMatch": ftm,
                                   "TextTransformations": _tts(*types)}}


def _and(parts: list[dict[str, Any]]) -> dict[str, Any]:
    return parts[0] if len(parts) == 1 else {"AndStatement": {"Statements": parts}}


BODY = {"Body": {"OversizeHandling": "CONTINUE"}}   # explicit: what is past the inspection limit is not seen
URL_SCHEME_RE = "^(https?|ftp|gopher|file)://"

# common legitimate traffic every custom rule must NOT match (a registry, not generated — 01-waf §5.2)
BENIGN: tuple[Request, ...] = (
    Request("GET", "/", (("User-Agent", "Mozilla/5.0"), ("Accept", "text/html"))),
    Request("GET", "/index.html"),
    Request("GET", "/static/app.js", (("Accept", "*/*"),)),
    Request("GET", "/api/v1/items?page=2&sort=name"),
    Request("POST", "/search", (("Content-Type", "application/x-www-form-urlencoded"),), b"q=select+a+plan+and+script+notes"),
    Request("POST", "/api/v1/login", (("Content-Type", "application/json"),), b'{"user":"alice","password":"correct horse"}'),
    # what an origin behind CloudFront → ALB sees on every request (the headers of PROXY_HEADERS)
    Request("GET", "/account", (("X-Forwarded-For", "203.0.113.7, 127.0.0.1"), ("X-Forwarded-Proto", "https"),
                                ("X-Forwarded-Port", "443"), ("X-Forwarded-Host", "shop.example.com"),
                                ("X-Real-IP", "203.0.113.7"), ("Forwarded", "for=203.0.113.7;proto=https"),
                                ("Via", "2.0 abc.cloudfront.net (CloudFront)"), ("X-Amz-Cf-Id", "Zx1-example=="),
                                ("X-Amzn-Trace-Id", "Root=1-67891233-abcdef012345678912345678"))),
)


# ---------------------------------------------------------------- samples from a template request
def _fill(s: str) -> str:
    """A template string with every variable replaced by a fixed sample value (OAST → a reserved .invalid host)."""
    return VAR.sub(lambda m: SAMPLE_OAST if "interactsh" in m.group(0) else SAMPLE_VALUE, s)


def sample(r: TemplateRequest, target: str | None = None, drop_header: str | None = None, body: str | None = None) -> Request:
    t = _fill(target if target is not None else r.target)
    if not t.startswith("/"):
        t = "/" + t
    hs = tuple((n, _fill(v)) for n, v, _ in r.headers if n.lower() not in ("host", "content-length")
               and n.lower() != (drop_header or "").lower())
    return Request(r.method, t, hs, _fill(body if body is not None else r.body).encode("latin-1", "replace"))


def _args(query: str) -> list[tuple[str, str]]:
    return [(p.partition("=")[0], p.partition("=")[2]) for p in query.split("&") if p]


def _with_arg(target: str, name: str, value: str) -> str:
    path, _, q = target.partition("?")
    return path + "?" + "&".join(f"{n}={value if n == name else v}" for n, v in _args(q))


def _fixed_prefix(s: str) -> str:
    return VAR.split(s, 1)[0]


# ---------------------------------------------------------------- extractors over a pinned template
@dataclass(frozen=True)
class Src:
    """The pinned template an extractor reads + how to quote it."""
    cve: str
    sha: str
    path: str
    lines: tuple[str, ...]

    def quote(self, line: int, token: str) -> Quote:
        if not (0 < line <= len(self.lines)) or token not in self.lines[line - 1]:
            raise ValueError(f"token {token!r} is not verbatim on {self.path}:{line}")
        return Quote(token, pocs.REPO, self.sha, self.path, line)

    def find(self, token: str, start: int = 1) -> int:
        return next((i for i in range(start, len(self.lines) + 1) if token in self.lines[i - 1]), 0)


def _query_traversal(t: Template, src: Src) -> list[Candidate]:
    out = []
    for r in t.attacks:
        for name, raw in _args(r.query):
            fixed = _fixed_prefix(raw)
            if VAR.search(name) or not fixed:
                continue
            once = urllib.parse.unquote(fixed)
            twice = urllib.parse.unquote(once)
            sep = "../" if "../" in twice else ("..\\" if "..\\" in twice else None)
            if not sep:
                continue
            double = sep not in once
            tts = ("URL_DECODE", "URL_DECODE") if double else ("URL_DECODE",)
            pos = [sample(r), sample(r, _with_arg(r.target, name, urllib.parse.quote(twice, safe=""))),
                   sample(r, _with_arg(r.target, name, twice)),
                   sample(r, _with_arg(r.target, name, re.sub(r"%[0-9a-f]{2}", lambda m: m.group(0).upper(), raw)))]
            neg = [sample(r, _with_arg(r.target, name, "about-us")), sample(r, _with_arg(r.target, name, "parent/child"))]
            out.append(Candidate("byte", byte({"SingleQueryArgument": {"Name": name}}, sep, "CONTAINS", *tts),
                                 (src.quote(r.line, f"{name}={fixed}"[:120]),), tuple(pos), tuple(neg), "exact",
                                 f"参数 {name} 里出现上级目录序列即计数；合法请求几乎不会这样写。"
                                 + ("两次 URL_DECODE：AWS 是否接受同类型重复 transformation 以 CheckCapacity 为准。" if double else "")))
    return out


def _trailing_slash(t: Template, src: Src) -> list[Candidate]:
    out = []
    for r in t.attacks:
        p = r.path
        if len(p) < 2 or not p.endswith("/") or VAR.search(p):
            continue
        sib = [o for o in t.requests if o.block == r.block and o is not r and o.path == p.rstrip("/")]
        if not sib:
            continue
        out.append(Candidate("byte", byte({"UriPath": {}}, p, "EXACTLY", "URL_DECODE"),
                             (src.quote(r.line, p), src.quote(sib[0].line, sib[0].path)),
                             (sample(r), sample(r, p[:-1] + "%2F")), (sample(sib[0]),), "exact",
                             f"只计数带尾斜杠的 {p}；同一端点的正常（无尾斜杠）调用不受影响。部署在路径前缀之下时把 EXACTLY 改为 ENDS_WITH。"))
    return out


def _named_header(t: Template, src: Src) -> list[Candidate]:
    out, seen = [], set()
    words = f"{t.name}\n{t.description}"
    for r in t.attacks:
        for n, _v, line in r.headers:
            low = n.lower()
            if low in GENERIC_HEADERS or VAR.search(n) or low in seen:
                continue
            m = re.search(rf"(?i)(?<![A-Za-z0-9-]){re.escape(n)}(?![A-Za-z0-9-])", words)
            if not m:
                continue   # a product header the template does not single out (X-Plex-*: every client sends it)
            seen.add(low)
            said = m.group(0)
            where = t.name_line if m.start() < len(t.name) else src.find(said, t.name_line + 1)
            stmt = {"SizeConstraintStatement": {"FieldToMatch": {"SingleHeader": {"Name": low}}, "ComparisonOperator": "GT",
                                                "Size": 0, "TextTransformations": _tts("NONE")}}
            out.append(Candidate("size", stmt, (src.quote(line, n), src.quote(where, said)), (sample(r),),
                                 (sample(r, drop_header=n),), "exact",
                                 f"外部客户端不应发送 {n}；若你的前置代理会合法注入它，先在代理处剥掉再启用。"))
    return out


def _ssrf_param(t: Template, src: Src) -> list[Candidate]:
    out = []
    for r in t.attacks:
        for name, raw in _args(r.query):
            dec = urllib.parse.unquote(raw)
            if VAR.search(name) or not (re.match(r"(?i)(https?|ftp|gopher|file)://\{\{", dec) or dec.startswith("{{interactsh")):
                continue
            parts = []
            if not VAR.search(r.path) and r.path not in ("", "/"):
                parts.append(byte({"UriPath": {}}, urllib.parse.unquote(r.path), "EXACTLY", "URL_DECODE"))
            parts.append({"RegexMatchStatement": {"RegexString": URL_SCHEME_RE, "FieldToMatch": {"SingleQueryArgument": {"Name": name}},
                                                  "TextTransformations": _tts("URL_DECODE", "LOWERCASE")}})
            token = f"{name}={_fixed_prefix(raw)}" if _fixed_prefix(raw) else f"{name}="
            pos = (sample(r, _with_arg(r.target, name, "http://example.invalid/x")),
                   sample(r, _with_arg(r.target, name, "HTTP%3A%2F%2FEXAMPLE.INVALID%2Fx")))
            neg = (sample(r, _with_arg(r.target, name, "/library/metadata/123")),)
            out.append(Candidate("and" if len(parts) > 1 else "regex", _and(parts), (src.quote(r.line, token),), pos, neg,
                                 "exact" if len(parts) > 1 else "heuristic",
                                 f"参数 {name} 的值是外部 URL 即计数；若你的用户合法地转码远程 URL 媒体，会被一并计数（中等误报）。"))
    return out


_XML_ELEM = re.compile(r"<([A-Za-z_][\w.-]{1,40})>([^<]*)</\1>")


def _sqli_element(t: Template, src: Src) -> list[Candidate]:
    if "CWE-89" not in t.cwes and "sqli" not in t.tags:
        return []
    out = []
    for r in t.attacks:
        for m in _XML_ELEM.finditer(r.body):
            if not (VAR.search(m.group(2)) or "'" in m.group(2)):
                continue
            elem = m.group(1)
            parts = []
            if not VAR.search(r.path) and r.path not in ("", "/"):
                parts.append(byte({"UriPath": {}}, r.path, "EXACTLY", "URL_DECODE"))
            parts += [byte(BODY, f"<{elem.lower()}>", "CONTAINS", "LOWERCASE"),
                      {"SqliMatchStatement": {"FieldToMatch": BODY, "TextTransformations": _tts("URL_DECODE", "HTML_ENTITY_DECODE"),
                                              "SensitivityLevel": "LOW"}}]
            line = src.find(f"<{elem}>", r.body_line or r.line)
            whole = m.group(0)
            pos = (sample(r, body=r.body.replace(whole, f"<{elem}>1' OR '1'='1</{elem}>")),)
            neg = (sample(r, body=r.body.replace(whole, f"<{elem}>10.0.0.1</{elem}>")),)
            out.append(Candidate("and", _and(parts), (src.quote(line, f"<{elem}>"),), pos, neg, "heuristic",
                                 f"端点与元素名 <{elem}> 逐字；注入判定用 AWS SqliMatch（LOW），签名非逐字、离线无法验证。"))
    return out


@dataclass(frozen=True)
class Extractor:
    name: str
    what: str                          # one line for the page / docs
    fn: Callable[[Template, Src], list[Candidate]]


EXTRACTORS: tuple[Extractor, ...] = (
    Extractor("query_traversal", "查询参数里的（多重）编码上级目录序列", _query_traversal),
    Extractor("trailing_slash", "同模板里无尾斜杠被拒、带尾斜杠放行的端点", _trailing_slash),
    Extractor("named_header", "模板名称/描述点名的专属 header", _named_header),
    Extractor("ssrf_param", "参数值是外部 URL（OAST 回连）", _ssrf_param),
    Extractor("sqli_element", "SQL 注入（CWE-89）落在 XML 元素里：端点 + 元素名 + SqliMatch", _sqli_element),
)


# ---------------------------------------------------------------- extractors over evidence sentences
# sentence ends: . ! ? followed by whitespace, or CJK 。！？ / newline — never a dot inside an IP, a path or a host
_SENT_END = re.compile(r"(?<=[.!?])\s+|(?<=[。！？])|\n+")
_EV_HEADER = re.compile(r"\b(X-[A-Za-z0-9-]{2,40}):\s*([A-Za-z0-9._/-]{3,60})")


@dataclass(frozen=True)
class Sentence:
    """One evidence sentence + where it sits: evidence_text(item)[offset:offset + len(text)] == text."""
    url: str
    item_id: str
    text: str
    offset: int

    def quote(self, m: re.Match[str]) -> Quote:
        """A quote of match `m` (found in self.text) with its span in the item's evidence_text."""
        return Quote(m.group(0), url=self.url, sentence=self.text, item_id=self.item_id,
                     span=(self.offset + m.start(), self.offset + m.end()))


def _sentences(items: list[Any]) -> list[Sentence]:
    out: list[Sentence] = []
    for it in items:
        text, pos = evidence_text(it), 0
        for part in _SENT_END.split(text):     # parts come in order: find(part, pos) is the part's own position
            at = text.find(part, pos)
            pos = at + len(part)
            st = part.strip()
            if 8 <= len(st) <= 400:
                out.append(Sentence(it.url, getattr(it, "item_id", None) or "", st, at + (len(part) - len(part.lstrip()))))
    return out


def _evidence_header(sentences: list[Sentence]) -> list[Candidate]:
    out, seen = [], set()
    for se in sentences:
        for m in _EV_HEADER.finditer(se.text):
            name, val = m.group(1), m.group(2)
            if (name.lower(), val) in seen:
                continue
            seen.add((name.lower(), val))
            # a generic / proxy header is not skipped here: PackRule refuses it ⇒ it is listed in `rejected` with why
            out.append(Candidate("byte", byte({"SingleHeader": {"Name": name.lower()}}, val, "CONTAINS", "NONE"),
                                 (se.quote(m),),
                                 (Request("GET", "/", ((name, val),)), Request("GET", "/x", ((name, f"a{val}b"),))),
                                 (Request("GET", "/"), Request("GET", "/", ((name, "benign"),))), "exact",
                                 f"证据逐字写出 {name}: {val}；内部组件/代理可能合法地带此 header。"))
    return out


# an endpoint the vendor names — the vulnerable one, or the one its workaround says to remove / block / disable
# (Neo 2026-11-18: 「WAF 规则我们需要自己写出来」; live 11-17: Apache Roller's CVE record says to remove the
# "/roller-services/xmlrpc" servlet mapping — the radar built no rule for it). The path must be in the sentence verbatim.
_EV_PATH = re.compile(r"(?<![\w/.:%-])(/[A-Za-z0-9_~-][A-Za-z0-9_.~-]*(?:/[A-Za-z0-9_.~-]+){0,6})(?![\w/])")
_EV_PATH_CONTEXT = re.compile(
    r"(?i)\b(?:endpoints?|servlet|mappings?|routes?|handlers?|paths?|URIs?|URLs?|interfaces?|APIs?|remove|block|"
    r"restrict|disable|deny|filter)\b|拦截|禁用|删除|移除|接口|端点|路径")
# never a rule: a filesystem path (an advisory's payload or install location), or a path so generic it is half a site
_EV_PATH_FS = ("/etc/", "/tmp/", "/var/", "/usr/", "/proc/", "/home/", "/bin/",  # noqa: S108 — paths refused, not used
               "/dev/", "/opt/", "/root/", "/sys/")
_EV_PATH_GENERIC = frozenset({"/api", "/admin", "/login", "/index.php", "/wp-admin", "/rest", "/graphql", "/v1", "/v2",
                              "/api/v1", "/api/v2", "/static", "/assets", "/console", "/manager/html", "/home"})


def _endpoint_ok(path: str) -> bool:
    low = path.lower().rstrip("/")
    if low in _EV_PATH_GENERIC or low.startswith(_EV_PATH_FS) or len(low) < Limits.RULEPACK_MIN_PATH:
        return False
    segs = [x for x in low.split("/") if x]
    return len(segs) >= 2 or "." in segs[-1]        # /roller-services/xmlrpc, /xmlrpc.php — not /blog


def _evidence_endpoint(sentences: list[Sentence]) -> list[Candidate]:
    out, seen = [], set()
    for se in sentences:
        if not _EV_PATH_CONTEXT.search(se.text):
            continue
        for m in _EV_PATH.finditer(se.text):
            path = m.group(1)
            if not _endpoint_ok(path) or path.lower() in seen:
                continue
            seen.add(path.lower())
            low = path.lower().rstrip("/")
            enc = "/" + "".join(f"%{ord(ch):02X}" if i == 0 else ch for i, ch in enumerate(low.lstrip("/")))
            # CONTAINS on the decoded, normalised, lower-cased path: a context root (/roller/roller-services/xmlrpc),
            # a doubled slash, %-encoding or upper case does not slip past it; the query string is not the path
            out.append(Candidate(
                "byte", byte({"UriPath": {}}, low, "CONTAINS", "URL_DECODE", "NORMALIZE_PATH", "LOWERCASE"),
                (se.quote(m),),
                (Request("POST", low), Request("GET", low.upper()), Request("POST", "/app" + low),
                 Request("POST", "/" + low), Request("POST", enc)),
                (Request("GET", "/"), Request("GET", "/search?q=" + low), Request("GET", low.rsplit("/", 1)[0] + "/other")),
                "heuristic",
                f"厂商原文点名了 {path}：拦截后该接口的全部请求都会被挡，包括正常使用（与厂商建议的关闭该接口等效）。"
                "先 Count 观察，确认业务不用这个接口再改 Block；正式修复仍是升级。"))
    return out


EVIDENCE_EXTRACTORS: tuple[tuple[str, Callable[[list[Sentence]], list[Candidate]]], ...] = (
    ("evidence_header", _evidence_header),
    ("evidence_endpoint", _evidence_endpoint),
)


# ---------------------------------------------------------------- templates (heuristic, triggered by evidence wording)
TEMPLATE_TRIGGERS: dict[str, re.Pattern[str]] = {
    "rate": re.compile(r"(?i)\b(brute[- ]?forc\w*|credential[- ]stuffing|password[- ]spray\w*)\b|暴力破解|撞库|密码喷洒"),
    "origin_lockdown": re.compile(r"(?i)\borigin (?:server|ip)s? (?:was |were |is |are )?(?:exposed|reached directly)\b"
                                  r"|\bbypass(?:es|ed|ing)? (?:the )?(?:cdn|cloudflare|cloudfront|waf)\b|绕过\s*(?:CDN|WAF)|直连源站|源站\s*IP\s*暴露"),
}
_DEFANGED_IP = re.compile(r"\b(\d{1,3})(\[\.\]|\(\.\)|\.)(\d{1,3})(\[\.\]|\(\.\)|\.)(\d{1,3})(\[\.\]|\(\.\)|\.)(\d{1,3})\b")


def _first(sentences: list[Sentence], rx: re.Pattern[str]) -> Quote | None:
    for se in sentences:
        m = rx.search(se.text)
        if m:
            return se.quote(m)
    return None


def _templates(sentences: list[Sentence]) -> list[Candidate]:
    out = []
    q = _first(sentences, TEMPLATE_TRIGGERS["rate"])
    if q:
        out.append(Candidate("rate", {"RateBasedStatement": {"Limit": Limits.RULEPACK_RATE_LIMIT, "AggregateKeyType": "IP",
                                                             "EvaluationWindowSec": 300}},
                             (q,), (Request("POST", "/login"),), (Request("GET", "/"),), "heuristic",
                             f"阈值 {Limits.RULEPACK_RATE_LIMIT} 次/5 分钟/IP 是模板默认值，不是证据值；NAT / 企业出口后的多用户会被聚合计数。"))
    q = _first(sentences, TEMPLATE_TRIGGERS["origin_lockdown"])
    if q:
        stmt = {"NotStatement": {"Statement": byte({"SingleHeader": {"Name": ORIGIN_HEADER}}, ORIGIN_SECRET_PLACEHOLDER, "EXACTLY", "NONE")}}
        out.append(Candidate("origin_lockdown", stmt, (q,),
                             (Request("GET", "/"), Request("GET", "/", ((ORIGIN_HEADER, "guess"),))),
                             (Request("GET", "/", ((ORIGIN_HEADER, ORIGIN_SECRET_PLACEHOLDER),)),), "heuristic",
                             "放在源站（ALB）的 web ACL：没有 CloudFront 注入的密钥 header 即计数。密钥不进规则包 —— "
                             f"{ORIGIN_SECRET_PLACEHOLDER} 由 Secrets Manager 动态引用替换；CloudFront 侧配 origin custom header，"
                             "安全组只放 CloudFront origin-facing 托管前缀列表。健康检查等直连流量也会被计数。"))
    ips: dict[str, Quote] = {}
    for se in sentences:
        for m in _DEFANGED_IP.finditer(se.text):
            if "[" not in m.group(0) and "(" not in m.group(0):
                continue   # only defanged spellings are IOCs (patterns: same rule as DNS) — a plain IP is a source / victim
            ip = ".".join(m.group(i) for i in (1, 3, 5, 7))
            try:
                if not ipaddress.ip_address(ip).is_global:
                    continue
            except ValueError:
                continue
            if ip not in ips:
                ips[ip] = se.quote(m)
    if ips:
        addrs = sorted(f"{ip}/32" for ip in ips)
        out.append(Candidate("ipset", {"IPSetReferenceStatement": {"ARN": IPSET_ARN_PLACEHOLDER}}, tuple(list(ips.values())[:5]),
                             tuple(Request(ip=ip) for ip in sorted(ips)), (Request(),), "exact",
                             "攻击者 IP 轮换极快，命中率随时间下降；共享出口（NAT / VPN / CDN）会误伤。"
                             f" 共 {len(addrs)} 个地址。"))
    return out


# ---------------------------------------------------------------- managed candidates
def managed(event: dict[str, Any], catalog: dict[str, list[mitigate.CveRules]], cwes: dict[str, list[str]],
            labels: dict[str, list[str]] | None = None) -> list[dict[str, Any]]:
    """mitigate.waf_plans without the located-target precondition (target "*" = the reader's own stack)."""
    plans = mitigate.waf_plans(event, [{"target_id": "*", "verdict": "affected"}], catalog, cwes, labels)
    return [{"tier": p.tier, "group": p.group, "group_label": mitigate.WAF_GROUPS[p.group].label, "rules": list(p.rules),
             "min_version": p.min_version, "reason": p.reason, "cves": list(p.cves), "appliable": p.appliable,
             "rule": mitigate.waf_rule(p, mitigate.paste_priority(p.group))} for p in plans]


# ---------------------------------------------------------------- build
def _reject(cve: str | None, source: str, extractor: str, reason: str, detail: str) -> dict[str, Any]:
    return {"cve": cve, "source": source, "extractor": extractor, "reason": reason, "detail": detail[:400]}


def _no_rule_reason(t: Template) -> tuple[str, str]:
    if t.protocol not in ("http", "requests"):
        return "not_http", f"模板协议是 {t.protocol or '未知'}，不是 HTTP —— WAF 只看 HTTP 请求"
    if not t.attacks:
        return "fingerprint_only", "模板只有指纹 / 预备请求（版本检测、内部提取），没有攻击请求"
    if any(HELPER.search(f"{r.target}\n{r.body}\n" + "\n".join(v for _, v, _ in r.headers)) for r in t.attacks):
        return "payload_by_helper", "攻击字节由模板 helper 在运行时生成（如 generate_java_gadget），模板里不存在逐字特征"
    return "no_verbatim_feature", "攻击请求里只有端点或随机值，没有攻击专属的逐字特征"


def _admit(c: Candidate, rule_id: str, extractor: str, cve: str | None, rejected: list[dict[str, Any]], source: str,
           ip_sets: dict[str, list[str]] | None = None) -> PackRule | None:
    """Candidate → PackRule (hard rules) → wafmatch gate. Anything that fails is listed in `rejected`, with why."""
    negatives = c.negatives + (BENIGN if c.kind not in ("rate", "origin_lockdown", "ipset") else ())
    try:
        rule = PackRule(rule_id, c.kind, extractor, c.statement, c.quotes, c.confidence, c.fp_note, c.positives, negatives,
                        cve, ip_set=({"addresses": sorted({f"{r.ip}/32" for r in c.positives}), "version": "IPV4"}
                                     if c.kind == "ipset" else None))
        offline = gate(c.statement, list(c.positives), list(negatives), ip_sets)
    except ValueError as e:
        rejected.append(_reject(cve, source, extractor, "constraint", str(e)))
        return None
    if offline["state"] == "fail":
        rejected.append(_reject(cve, source, extractor, offline["reason"], offline["detail"]))
        return None
    return replace(rule, verified={"offline": offline, "capacity": {"state": "unchecked"}})


@dataclass(frozen=True)
class RulePack:
    event_id: str
    managed: tuple[dict[str, Any], ...]
    custom: tuple[PackRule, ...]
    templates: tuple[PackRule, ...]
    rejected: tuple[dict[str, Any], ...]
    poc: tuple[dict[str, Any], ...]
    no_rule: str | None = None     # why there is nothing to deploy at the edge (said, never an empty pack in silence)

    @property
    def empty(self) -> bool:
        # a CVE event with no template / an unavailable PoC source still gets a pack: the page says which, not nothing
        return not (self.managed or self.custom or self.templates or self.rejected or self.poc)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"event_id": self.event_id, "name": pack_name(self.event_id), "note": mitigate.MITIGATION_NOTE,
                             "managed": list(self.managed), "custom": [r.as_dict() for r in self.custom],
                             "templates": [r.as_dict() for r in self.templates], "rejected": list(self.rejected),
                             "poc": list(self.poc), "license": pocs.LICENSE if any(
                                 q.repo for r in self.custom for q in r.source_quotes) else None,
                             "capacity": {"state": "unchecked", "wcu": None, "detail": "尚未调用 CheckCapacity"},
                             "no_rule": self.no_rule}
        d["hash"] = pack_hash(d)
        return d


def pack_name(event_id: str) -> str:
    return "radar-" + re.sub(r"[^A-Za-z0-9-]", "", event_id.replace("_", "-"))[:100] + "-pack"


def pack_hash(d: dict[str, Any]) -> str:
    """Content hash of what CheckCapacity and the reader see (rules + managed), not of timestamps / capacity."""
    body = {k: d.get(k) for k in ("managed", "custom", "templates")}
    for k in ("custom", "templates"):
        body[k] = [{x: r[x] for x in ("rule_id", "statement", "ip_set") if x in r} for r in body[k] or []]
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]


def _poc_row(cve: str, e: dict[str, Any]) -> dict[str, Any]:
    return {"cve": cve, "state": e.get("state", "unavailable"), "path": e.get("path"), "sha": e.get("sha"),
            "url": pocs.template_url(e["sha"], e["path"]) if e.get("sha") and pocs.safe_path(e.get("path")) else None,
            "error": e.get("error")}


def failed(event: dict[str, Any], poc: dict[str, dict[str, Any]], err: BaseException) -> RulePack:
    """The pack of an event whose build raised: no rule, one `rejected` row naming the error, the PoC rows as read.
    The station writes this instead of dying — the page says 生成失败 and why, the other events and the M3 ledger
    are still written (review of p1/rulepack: one bad template used to abort the whole mitigate run)."""
    cves = sorted({c.upper() for c in event.get("cves") or []})
    return RulePack(event["event_id"], (), (), (), (_reject(None, "pack", "build", "unparseable",
                                                            f"规则包生成失败：{type(err).__name__}: {err}"),),
                    tuple(_poc_row(c, poc.get(c) or {"state": "unavailable"}) for c in cves))


def build(event: dict[str, Any], items: list[Any], poc: dict[str, dict[str, Any]],
          catalog: dict[str, list[mitigate.CveRules]], cwes: dict[str, list[str]],
          labels: dict[str, list[str]] | None = None) -> RulePack:
    """The pack of one event. `event` = {event_id, cves, product}; `items` = its evidence (title, text, url);
    `poc` = radar.pocs.refresh output for the event's CVEs."""
    eid = event["event_id"]
    short = re.sub(r"[^A-Za-z0-9]", "", eid.removeprefix("ev_"))[:12]
    rejected: list[dict[str, Any]] = []
    custom: list[PackRule] = []
    poc_rows: list[dict[str, Any]] = []
    n = 0
    for cve in sorted({c.upper() for c in event.get("cves") or []}):
        e = poc.get(cve) or {"state": "unavailable"}
        row = _poc_row(cve, e)
        poc_rows.append(row)
        if row["state"] != "found" or not e.get("text"):
            continue
        try:
            tpl = pocs.parse_template(e["text"])
        except Exception as ex:   # noqa: BLE001 — feed-controlled text: any parse failure is this CVE's visible rejection
            # UnsupportedYaml is the expected case; anything else is a reader bug the bytes triggered — named by its type
            why = str(ex) if isinstance(ex, ValueError) else f"{type(ex).__name__}: {ex}"
            rejected.append(_reject(cve, "nuclei", "parse", "unparseable", f"模板无法按 YAML 子集解析：{why}"))
            continue
        src = Src(cve, e["sha"], e["path"], tuple(e["text"].split("\n")))
        found = 0
        for ex in EXTRACTORS:
            try:
                cands = ex.fn(tpl, src)
            except ValueError as err:   # an extractor could not quote verbatim — that candidate does not exist
                rejected.append(_reject(cve, "nuclei", ex.name, "not_verbatim", str(err)))
                continue
            except Exception as err:   # noqa: BLE001 — an extractor tripped on a template shape: that extractor only
                rejected.append(_reject(cve, "nuclei", ex.name, "extractor_error", f"{type(err).__name__}: {err}"))
                continue
            for c in cands:
                n += 1
                found += 1
                r = _admit(c, f"radar-{short}-{ex.name.replace('_', '-')}-{n}", ex.name, cve, rejected, "nuclei")
                if r:
                    custom.append(r)
        if not found:
            reason, detail = _no_rule_reason(tpl)
            rejected.append(_reject(cve, "nuclei", "-", reason, detail))
    sentences = _sentences(items)
    for name, fn in EVIDENCE_EXTRACTORS:
        for c in fn(sentences):
            n += 1
            r = _admit(c, f"radar-{short}-{name.replace('_', '-')}-{n}", name, None, rejected, "evidence")
            if r:
                custom.append(r)
    templates: list[PackRule] = []
    for c in _templates(sentences):
        n += 1
        ip_sets = {IPSET_ARN_PLACEHOLDER: [f"{r.ip}/32" for r in c.positives]} if c.kind == "ipset" else None
        r = _admit(c, f"radar-{short}-{c.kind.replace('_', '-')}-{n}", c.kind, None, rejected, "template", ip_sets)
        if r:
            templates.append(r)
    keep = Limits.RULEPACK_MAX_RULES
    over = (custom + templates)[keep:]
    for r in over:
        rejected.append(_reject(r.cve, "pack", r.extractor, "over_rule_cap", f"{r.rule_id}: 规则包上限 {keep} 条"))
    custom, templates = custom[:keep], templates[:max(0, keep - len(custom))]
    plans = tuple(managed(event, catalog, cwes, labels))
    return RulePack(eid, plans, tuple(custom), tuple(templates), tuple(rejected), tuple(poc_rows),
                    None if (plans or custom or templates) else no_rule_reason(event, cwes))


def no_rule_reason(event: dict[str, Any], cwes: dict[str, list[str]]) -> str:
    """Why a vulnerability gets no edge rule — in words the reader can check (Neo 2026-11-19: 「能用 WAF 解决的，先用 WAF
    挡一下」; an empty pack said nothing). The weakness, when known, is named; a rule nobody can derive is not invented."""
    known = sorted({w for ws in cwes.values() for w in ws})
    if known:
        return (f"弱点类型 {'、'.join(known)} 没有对应的 AWS 托管规则，公告也没有给出攻击请求的特征（端点、参数、请求头）："
                "边缘规则会误拦正常流量或拦不住，只能打补丁或在主机上缓解")
    return ("公告没有给出攻击请求的特征（端点、参数、请求头），也没有弱点类型（CWE）：写不出既拦得住、又不误拦正常流量的"
            "边缘规则，只能打补丁或在主机上缓解")


def check_quotes(pack: dict[str, Any], get_text: Callable[[str], str],
                 get_item: Callable[[str], Any | None]) -> list[dict[str, Any]]:
    """--check (W5, 01-waf §4 「回源核验」): every quote against its SOURCE, re-read — never against the copy in the pack.
    A template quote: the text at pocs.raw_url(sha, path) (get_text) has the token on the quoted line. An evidence
    quote: the item re-read from the store (get_item) has the token at exactly evidence_text(item)[span] and contains
    the sentence. Returns the failures — empty = every rule's provenance holds. A source that cannot be read is a
    failure with its reason (fetch_failed / source_missing / no_span), never a pass."""
    bad: list[dict[str, Any]] = []
    cache: dict[str, str] = {}

    def fail(r: dict[str, Any], q: dict[str, Any], reason: str, detail: str) -> None:
        bad.append({"event_id": pack.get("event_id"), "rule_id": r["rule_id"], "quote": q, "reason": reason,
                    "detail": detail[:300]})
    for r in (pack.get("custom") or []) + (pack.get("templates") or []):
        for q in r.get("source_quotes") or []:
            if q.get("repo"):
                try:
                    url = pocs.raw_url(q["sha"], q["path"])   # a stored row is re-gated: never a raw splice
                    if url not in cache:
                        cache[url] = get_text(url)
                except Exception as e:   # noqa: BLE001 — reported as a failed check, with the error
                    fail(r, q, "fetch_failed", f"{type(e).__name__}: {e}")
                    continue
                if not verify_quote(q, cache[url]):
                    fail(r, q, "not_verbatim", f"{q['path']}:{q['line']} at {q['sha'][:10]} does not contain {q['token']!r}")
                continue
            if not (q.get("item_id") and len(q.get("span") or []) == 2):
                fail(r, q, "no_span", "evidence quote without item_id + span: nothing to read back")
                continue
            try:
                item = get_item(q["item_id"])
            except Exception as e:   # noqa: BLE001 — the store read failed: a failed check, with the error
                fail(r, q, "fetch_failed", f"{type(e).__name__}: {e}")
                continue
            if item is None:
                fail(r, q, "source_missing", f"item {q['item_id']} is not in the store")
            elif not verify_quote(q, evidence_text(item)):
                fail(r, q, "not_verbatim", f"item {q['item_id']}[{q['span'][0]}:{q['span'][1]}] is not {q['token']!r}")
    return bad


def stored_templates(store: Any, pack: dict[str, Any]) -> dict[str, str]:
    """raw_url(sha, path) → text of the template rows the mitigate station stored for the pack's CVEs — the pinned
    bytes without a network call (default --check source; --refetch reads GitHub at the same SHA instead)."""
    rows = store.get_source_states([pocs.TPL_KEY + p["cve"] for p in pack.get("poc") or []])
    return {pocs.raw_url(r["sha"], r["path"]): r["text"] for r in rows.values()
            if r and r.get("sha") and pocs.safe_path(r.get("path")) and isinstance(r.get("text"), str)}


def check_store(store: Any, now: Any, refetch: Callable[[str], str] | None = None,
                event_ids: list[str] | None = None) -> tuple[int, list[dict[str, Any]]]:
    """--check over the stored packs (the station's window, or `event_ids`): (packs checked, failures)."""
    if event_ids is None:
        since = timeutil.iso(now - timedelta(days=Limits.MITIGATE_WINDOW_DAYS))
        event_ids = [ev.event_id for ev in store.events_updated_since(since)]
    packs = [p for p in store.get_source_states([key(e) for e in event_ids]).values() if p and p.get("event_id")]
    bad: list[dict[str, Any]] = []
    for pack in packs:
        texts = {} if refetch else stored_templates(store, pack)

        def get_text(url: str, texts: dict[str, str] = texts) -> str:
            if refetch:
                return refetch(url)
            if url not in texts:
                raise KeyError(f"pinned bytes {url.removeprefix(pocs.RAW_URL)[:60]} not stored (template moved on — use --refetch)")
            return texts[url]
        ids = sorted({q["item_id"] for k in ("custom", "templates") for r in pack.get(k) or []
                      for q in r.get("source_quotes") or [] if q.get("item_id")})
        items = {it.item_id: it for it in store.get_items(ids)} if ids else {}
        bad += check_quotes(pack, get_text, items.get)
    return len(packs), bad


def cli(argv: list[str], store: Any, now: Any, get: Callable[[str], str] = pocs.get) -> int:
    """`--check [--refetch] [EVENT_ID …]` (scripts/rulepack_check.py; scripts/verify.sh runs it): one JSON line per
    failure, a summary line, exit 1 on any failure — and also when there was no pack to check (nothing checked ≠ ok)."""
    if "--check" not in argv:
        print("usage: rulepack_check.py --check [--refetch] [EVENT_ID ...]")
        return 2
    ids = [a for a in argv if a.startswith("ev_")] or None
    n, bad = check_store(store, now, get if "--refetch" in argv else None, ids)
    for b in bad:
        print(json.dumps(b, ensure_ascii=False))
    print(json.dumps({"packs_checked": n, "failures": len(bad)}))
    return 1 if bad or n == 0 else 0


def quote_href(q: dict[str, Any]) -> str | None:
    """THE link of a quote (page + markdown): a template quote → the file at its pinned commit, line anchor; an
    evidence quote → its item's URL, only when http(s) (an item URL is feed data: a `javascript:` URL is no link)."""
    if q.get("repo"):
        return f"{pocs.template_url(q['sha'], q['path'])}#L{q['line']}" if pocs.safe_path(q.get("path")) else None
    url = q.get("url") or ""
    return url if re.match(r"https?://", url) else None


def public(row: dict[str, Any] | None) -> dict[str, Any] | None:
    """The pack as the event page shows it: the stored row + its five renderings (radar.packrender, one source)."""
    if not row or not row.get("event_id"):
        return None
    from radar import packrender
    rules = {k: [{**r, "what": packrender.describe(r["statement"]),
                  "source_quotes": [{**q, "href": quote_href(q)} for q in r.get("source_quotes") or []]}
                 for r in row.get(k) or []] for k in ("custom", "templates")}
    return {**row, **rules, "renderings": packrender.render_all(row)}
