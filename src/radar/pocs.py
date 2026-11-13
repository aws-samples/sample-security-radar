"""Structured PoC enrichment per CVE: projectdiscovery/nuclei-templates (MIT) → pinned template text → request features.

Why (docs/research/action/08-poc-sources.md): the radar's evidence carries no HTTP-level features — custom WAF rules
came out of 0 of 309 live events. nuclei templates state the attack request field by field (method, path, headers,
body); 17 of those 309 events have a template with an attack-specific, verbatim feature. Templates arrive a median
14 days after the CVE ⇒ this is a lookup next to cvemeta / EPSS, not a new source: it adds no event, no cluster key.

Flow (one call per mitigate run, `refresh`):
  1. once a UTC day: GET cves.json-checksum.txt (33 B, the MD5 of cves.json); unchanged ⇒ nothing else is fetched
  2. changed ⇒ GET cves.json (JSONL, ~2.3 MB) → {CVE: file_path}; the body's MD5 must equal the checksum (a torn read
     between two files on main is refused, retried next run) → index shards `__poc_index__#<n>`
  3. per CVE of a windowed event whose index row is new / moved / older than POC_RECHECK_DAYS: commits API → newest
     commit SHA of that path → raw template AT THAT SHA (never `main`: a rule quotes bytes that never move) →
     one row `__poc_tpl__#<CVE>` {sha, path, text}; ledger `__poc_meta__#<n>` {cve: {state, path, sha, …}}
Every fetch goes through radar.fetch.http_get with HOSTS as the allowlist (redirects included). Every row written is
size-checked (Limits.POC_ROW_MAX_BYTES) before the put — an oversize row is refused visibly, never truncated silently.

Degradation (degradation-and-guards §1): a failed step keeps yesterday's data and says so — `state` per CVE is
  found | no_template (the index was read and has no row) | unavailable (the index was never read: NOT "no template")
  | too_large | error. The page words them apart: 「PoC 来源暂不可用」 is never shown as 「无规则」.

Templates are parsed with a small YAML-subset reader (`load_yaml`): the Lambda bundle refuses native extensions
(scripts/build-lambda.sh) and PyYAML ships one. Anything outside the subset (anchors, aliases, flow maps, folded
scalars) raises — the template is then `rejected: unparseable`, never half-read. tests cross-check it with PyYAML."""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from radar import fetch, timeutil
from radar.limits import Limits

REPO = "projectdiscovery/nuclei-templates"
LICENSE = "MIT — Copyright (c) 2025 ProjectDiscovery, Inc. (nuclei-templates/LICENSE.md)"
HOSTS = frozenset({"raw.githubusercontent.com", "api.github.com"})
CHECKSUM_URL = f"https://raw.githubusercontent.com/{REPO}/main/cves.json-checksum.txt"
INDEX_URL = f"https://raw.githubusercontent.com/{REPO}/main/cves.json"
COMMITS_URL = f"https://api.github.com/repos/{REPO}/commits?per_page=1&path="
RAW_URL = f"https://raw.githubusercontent.com/{REPO}/"     # + <sha>/<path>
INDEX_KEY = "__poc_index__"     # header {checksum, checked_on, fetched_at, count, error, lookups}; shards INDEX_KEY#<n>
META_KEY = "__poc_meta__"       # shards META_KEY#<n> {cve: {state, path, sha, checked_at, …}}
META_SHARDS = 64
TPL_KEY = "__poc_tpl__#"        # + CVE → {sha, path, text}: one template per row (bounded by POC_TEMPLATE_MAX_BYTES)
SHA = re.compile(r"[0-9a-f]{40}")
STATES = ("found", "no_template", "unavailable", "too_large", "error")
log = logging.getLogger(__name__)


def get(url: str) -> str:
    """THE fetch of this module: https on HOSTS only, every redirect hop too (radar.fetch allowlist)."""
    return fetch.http_get(url, {"Accept": "application/vnd.github+json" if "api.github.com" in url else "*/*"},
                          allow_hosts=HOSTS).body


# ---------------------------------------------------------------- YAML subset
class Located(str):
    """A string scalar that remembers the 1-based line its text starts on (block scalars: the first content line)."""
    line: int = 0

    def __new__(cls, s: str, line: int) -> Located:  # noqa: PYI034 — str subclass: returns the new instance
        o = super().__new__(cls, s)
        o.line = line
        return o


class UnsupportedYaml(ValueError):
    pass


_KEY = re.compile(r"""^(?:"((?:[^"\\]|\\.)*)"|'((?:[^']|'')*)'|([^\s#'"\[\]{},:][^:#]*?|[^\s#'"\[\]{},:]))\s*:(?:\s+|$)(.*)$""")


def _strip_comment(s: str) -> str:
    out, q = [], None
    for i, ch in enumerate(s):
        if q:
            out.append(ch)
            if ch == q and not (q == '"' and i and s[i - 1] == "\\"):
                q = None
        elif ch in "'\"" and (not out or out[-1] in " [,:"):
            q = ch
            out.append(ch)
        elif ch == "#" and (not out or out[-1] in " \t"):
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


def _scalar(raw: str, line: int) -> Any:
    s = _strip_comment(raw).strip()
    if not s:
        return None
    if s[0] in "&*!{>":
        raise UnsupportedYaml(f"line {line}: {s[:20]!r} (anchor / alias / tag / flow map / folded scalar)")
    if s[0] == '"':
        if not s.endswith('"') or len(s) < 2:
            raise UnsupportedYaml(f"line {line}: multi-line double-quoted scalar")
        try:
            return Located(json.loads(s), line)
        except ValueError as e:   # a YAML escape JSON does not share (\x41, \/ …)
            raise UnsupportedYaml(f"line {line}: double-quoted escape outside the subset ({e})") from e
    if s[0] == "'":
        if not s.endswith("'") or len(s) < 2:
            raise UnsupportedYaml(f"line {line}: multi-line single-quoted scalar")
        return Located(s[1:-1].replace("''", "'"), line)
    if s[0] == "[":
        if not s.endswith("]"):
            raise UnsupportedYaml(f"line {line}: multi-line flow sequence")
        inner = s[1:-1].strip()
        return [_scalar(x, line) for x in re.split(r",\s*", inner)] if inner else []
    low = s.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~"):
        return None
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    return Located(s, line)


class _Reader:
    def __init__(self, text: str) -> None:
        self.lines = text.replace("\r\n", "\n").split("\n")
        self.i = 0

    def _sig(self) -> int | None:
        """Index of the next line that is not blank / comment-only (from self.i)."""
        j = self.i
        while j < len(self.lines):
            st = self.lines[j].strip()
            if st and not st.startswith("#"):
                if "\t" in self.lines[j][: len(self.lines[j]) - len(self.lines[j].lstrip())]:
                    raise UnsupportedYaml(f"line {j + 1}: tab indentation")
                return j
            j += 1
        return None

    @staticmethod
    def _indent(s: str) -> int:
        return len(s) - len(s.lstrip(" "))

    def block(self, min_indent: int) -> Any:
        j = self._sig()
        if j is None or self._indent(self.lines[j]) < min_indent:
            return None
        ind = self._indent(self.lines[j])
        body = self.lines[j].strip()
        if body == "-" or body.startswith("- "):
            return self.seq(ind)
        return self.mapping(ind)

    def block_scalar(self, header: str, parent: int) -> Located:
        h = _strip_comment(header).strip()
        if not re.fullmatch(r"\|[-+]?", h):
            raise UnsupportedYaml(f"line {self.i}: block scalar header {h!r}")
        out: list[str] = []
        first, ind = None, None
        while self.i < len(self.lines):
            s = self.lines[self.i]
            if s.strip() == "":
                if ind is not None:      # blank lines before the first content line are not part of the text
                    out.append("")
                self.i += 1
                continue
            if self._indent(s) <= parent:
                break
            if ind is None:
                ind, first = self._indent(s), self.i + 1
            if self._indent(s) < ind:
                break
            out.append(s[ind:])
            self.i += 1
        while out and out[-1] == "" and h != "|+":
            out.pop()
        # leave trailing blank lines for the next construct
        text = "\n".join(out)
        if h == "|":
            text += "\n" if text else ""
        elif h == "|+":
            text += "\n"
        return Located(text, first or self.i)

    def value(self, rest: str, indent: int, line: int) -> Any:
        r = _strip_comment(rest).strip()
        if r.startswith("|"):
            return self.block_scalar(r, indent)
        if r:
            return _scalar(rest, line)
        j = self._sig()
        if j is None:
            return None
        nxt = self._indent(self.lines[j])
        st = self.lines[j].strip()
        if nxt > indent or (nxt == indent and (st == "-" or st.startswith("- "))):
            return self.block(nxt)
        return None

    def mapping(self, ind: int) -> dict[str, Any]:
        out: dict[str, Any] = {}
        while True:
            j = self._sig()
            if j is None or self._indent(self.lines[j]) != ind:
                if j is not None and self._indent(self.lines[j]) > ind:
                    raise UnsupportedYaml(f"line {j + 1}: unexpected indentation")
                return out
            body = self.lines[j].strip()
            if body == "-" or body.startswith("- "):
                return out
            m = _KEY.match(body)
            if not m:
                raise UnsupportedYaml(f"line {j + 1}: not a `key: value` line: {body[:40]!r}")
            key = (m.group(1) if m.group(1) is not None else m.group(2) if m.group(2) is not None else m.group(3)).strip()
            self.i = j + 1
            if key in out:
                raise UnsupportedYaml(f"line {j + 1}: duplicate key {key!r}")
            out[key] = self.value(m.group(4), ind, j + 1)

    def seq(self, ind: int) -> list[Any]:
        out: list[Any] = []
        while True:
            j = self._sig()
            if j is None or self._indent(self.lines[j]) != ind:
                return out
            body = self.lines[j].strip()
            if not (body == "-" or body.startswith("- ")):
                return out
            rest = body[1:].lstrip(" ")
            off = ind + (len(body) - len(rest))
            if not rest:
                self.i = j + 1
                out.append(self.value("", ind, j + 1))
            elif rest.startswith("|"):
                self.i = j + 1
                out.append(self.block_scalar(rest, ind))
            elif _KEY.match(rest):
                # "- key: v" — a mapping whose first key sits on the dash line: re-read the line at the content column
                self.lines[j] = " " * off + rest
                self.i = j
                out.append(self.mapping(off))
            else:
                self.i = j + 1
                out.append(_scalar(rest, j + 1))


def load_yaml(text: str) -> Any:
    r = _Reader(text)
    doc = r.block(0)
    if r._sig() is not None:
        raise UnsupportedYaml(f"line {r._sig() + 1}: trailing content not read")   # type: ignore[operator]
    return doc


# ---------------------------------------------------------------- nuclei template → requests
VAR = re.compile(r"\{\{[^{}]*\}\}")
HELPER = re.compile(r"\{\{\s*[a-z_][a-z0-9_]*\s*\(")     # {{base64(...)}}, {{generate_java_gadget(...)}}
BASE_VARS = ("{{BaseURL}}", "{{RootURL}}")


@dataclass(frozen=True)
class TemplateRequest:
    block: int                   # index in http[]
    index: int                   # index within the block (raw[] / path[])
    method: str
    target: str                  # request target as written, {{BaseURL}} / {{RootURL}} stripped (may hold other {{vars}})
    line: int                    # template line of the request line / path entry
    headers: tuple[tuple[str, str, int], ...]   # (name, value, line)
    body: str
    body_line: int | None
    probe: str                   # "" = an attack request; else why it is a probe (never a rule)

    @property
    def path(self) -> str:
        return self.target.split("?", 1)[0]

    @property
    def query(self) -> str:
        return self.target.split("?", 1)[1] if "?" in self.target else ""


@dataclass(frozen=True)
class Template:
    template_id: str
    name: str
    name_line: int
    description: str
    severity: str
    cwes: tuple[str, ...]
    tags: tuple[str, ...]
    protocol: str                # http | network | javascript | … (first protocol key found)
    requests: tuple[TemplateRequest, ...]

    @property
    def attacks(self) -> tuple[TemplateRequest, ...]:
        return tuple(r for r in self.requests if not r.probe)


PROTOCOLS = ("http", "requests", "network", "tcp", "javascript", "dns", "ssl", "websocket", "headless", "code", "file")


def _strip_base(target: str) -> str:
    t = target.strip()
    for b in BASE_VARS:
        if t.startswith(b):
            t = t[len(b):]
            break
    return t or "/"


def _probe_block(block: dict[str, Any]) -> str:
    """Why a whole http[] block is preparatory: its matchers are all `internal: true` (nuclei: the result is not
    reported — used to steer a flow) or every extractor is internal (it pulls a value later requests use)."""
    ms = block.get("matchers") or []
    if ms and all(isinstance(m, dict) and m.get("internal") is True for m in ms):
        return "internal matchers (fingerprint / flow step)"
    ex = block.get("extractors") or []
    if ex and all(isinstance(e, dict) and e.get("internal") is True for e in ex):
        return "internal extractor (fetches a target-specific value)"
    return ""


def _fingerprint(method: str, target: str, body: str) -> bool:
    return method == "GET" and not body.strip() and target.split("?", 1)[0] in ("", "/") and "?" not in target


def _node(v: Any, kind: type | tuple[type, ...], where: str, default: Any = None) -> Any:
    """A template node of the expected YAML type, or UnsupportedYaml. The template is third-party (the feed controls it):
    `info: oops`, `raw: 123`, `headers: [x]` once reached `.get` / `.line` / `.items` and crashed the whole mitigate run
    (review of p1/rulepack) — a wrong-typed node is now the same `rejected: unparseable` as any other unreadable YAML."""
    if v is None:
        return default
    ok = isinstance(v, kind) and not (isinstance(v, bool) and bool not in (kind if isinstance(kind, tuple) else (kind,)))
    if not ok:
        names = "/".join(k.__name__ for k in (kind if isinstance(kind, tuple) else (kind,)))
        raise UnsupportedYaml(f"{where}: expected {names}, got {type(v).__name__} {str(v)[:30]!r}")
    return v


def _scalar_text(v: Any, where: str) -> Located:
    """A string scalar WITH its line (Located): a quoted line number is what a rule's provenance stands on."""
    return _node(v, Located, where)


def _raw_request(raw: Any, block: int, index: int, probe: str) -> TemplateRequest:
    raw = _scalar_text(raw, f"http[{block}].raw[{index}]")
    lines = str(raw).split("\n")
    k = 0
    while k < len(lines) and not lines[k].strip():
        k += 1
    if k == len(lines):
        raise UnsupportedYaml(f"line {raw.line}: empty raw request")
    req_line = lines[k].strip().split(" ")
    if len(req_line) < 2:
        raise UnsupportedYaml(f"line {raw.line + k}: request line {lines[k][:40]!r}")
    method, target = req_line[0].upper(), _strip_base(req_line[1])
    headers, n = [], k + 1
    while n < len(lines) and lines[n].strip():
        name, sep, val = lines[n].partition(":")
        if sep:
            headers.append((name.strip(), val.strip(), raw.line + n))
        n += 1
    body_lines = lines[n + 1:] if n < len(lines) else []
    body = "\n".join(body_lines).strip("\n")
    first_body = next((i for i, x in enumerate(body_lines) if x.strip()), None)
    why = probe or ("fingerprint request (GET of the site root)" if _fingerprint(method, target, body) else "")
    return TemplateRequest(block, index, method, target, raw.line + k, tuple(headers), body,
                           raw.line + n + 1 + first_body if first_body is not None else None, why)


_SCALAR = (str, int, bool)     # str: a Located, or a piece of a comma-split scalar


def parse_template(text: str) -> Template:
    """nuclei template text → Template. Every node read is type-checked (_node): anything else is UnsupportedYaml."""
    doc = load_yaml(text)
    if not isinstance(doc, dict):
        raise UnsupportedYaml("template is not a mapping")
    info = _node(doc.get("info"), dict, "info", {})
    cls = _node(info.get("classification"), dict, "info.classification", {})
    cwe = _node(cls.get("cwe-id"), (list, *_SCALAR), "info.classification.cwe-id", [])
    cwe_list = cwe if isinstance(cwe, list) else str(cwe).split(",")
    cwes = tuple(str(_node(c, _SCALAR, "cwe-id[]")).strip().upper() for c in cwe_list if str(c).strip())
    tags_raw = _node(info.get("tags"), (list, Located), "info.tags", "")
    tags = tuple(str(_node(t, _SCALAR, "tags[]")).strip().lower()
                 for t in (tags_raw if isinstance(tags_raw, list) else str(tags_raw).split(",")) if str(t).strip())
    protocol = next((p for p in PROTOCOLS if p in doc), "")
    reqs: list[TemplateRequest] = []
    if protocol in ("http", "requests"):
        for b, block in enumerate(_node(doc.get(protocol), list, protocol, [])):
            block = _node(block, dict, f"{protocol}[{b}]", {})
            for k in ("matchers", "extractors", "raw", "path"):
                _node(block.get(k), list, f"{protocol}[{b}].{k}")
            probe = _probe_block(block)
            for i, raw in enumerate(block.get("raw") or []):
                reqs.append(_raw_request(raw, b, i, probe))
            method = str(_node(block.get("method"), Located, f"{protocol}[{b}].method", "GET")).upper()
            hdr_map = _node(block.get("headers"), dict, f"{protocol}[{b}].headers", {})
            hdrs = tuple((str(k), str(_node(v, _SCALAR, f"headers.{k}")), getattr(v, "line", 0)) for k, v in hdr_map.items())
            body = _node(block.get("body"), Located, f"{protocol}[{b}].body", "")
            for i, p in enumerate(block.get("path") or []):
                tgt = _strip_base(str(_scalar_text(p, f"{protocol}[{b}].path[{i}]")))
                why = probe or ("fingerprint request (GET of the site root)" if _fingerprint(method, tgt, str(body)) else "")
                reqs.append(TemplateRequest(b, i, method, tgt, getattr(p, "line", 0), hdrs, str(body),
                                            getattr(body, "line", None) if body else None, why))
    name = _node(info.get("name"), Located, "info.name", "")
    tid = _node(doc.get("id"), _SCALAR, "id", "")
    return Template(str(tid), str(name), getattr(name, "line", 0), str(_node(info.get("description"), Located, "info.description", "")),
                    str(_node(info.get("severity"), Located, "info.severity", "")), cwes, tags, protocol, tuple(reqs))


# ---------------------------------------------------------------- ledger + refresh
def _index_shard(cve: str) -> str:
    return f"{INDEX_KEY}#{int(hashlib.sha1(cve.encode(), usedforsecurity=False).hexdigest(), 16) % Limits.POC_INDEX_SHARDS}"


def _meta_shard(cve: str) -> str:
    return f"{META_KEY}#{int(hashlib.sha1(cve.encode(), usedforsecurity=False).hexdigest(), 16) % META_SHARDS}"


class RowTooLarge(ValueError):
    pass


def _check_size(key: str, row: dict[str, Any]) -> None:
    n = len(json.dumps(row, ensure_ascii=False).encode())
    if n > Limits.POC_ROW_MAX_BYTES:
        raise RowTooLarge(json.dumps({"error": "poc_row_too_large", "message": f"{key} would exceed the PoC row cap",
                                      "actual_bytes": n, "max_bytes": Limits.POC_ROW_MAX_BYTES}))


def _put(store: Any, key: str, row: dict[str, Any]) -> None:
    """Every PoC row goes through here: refused (RowTooLarge, with actual and limit) before it can fail the item limit."""
    _check_size(key, row)
    store.put_source_state(key, row)


# a repo-relative template path: segments that start with a letter / digit (no "", ".", ".." segment, no leading "/"),
# a closed character set (nothing a URL or a markdown link would read as syntax), ending .yaml / .yml
TEMPLATE_PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,120}(?:/[A-Za-z0-9][A-Za-z0-9._+-]{0,120}){0,12}\.ya?ml")


def safe_path(path: Any) -> bool:
    # "." / ".." segments cannot match: every segment starts with a letter or digit
    return isinstance(path, str) and TEMPLATE_PATH.fullmatch(path) is not None


def checked_path(path: Any) -> str:
    """THE gate for a feed-controlled file_path before it reaches a URL / link (review of p1/rulepack: `../` from
    cves.json was spliced into RAW_URL + sha + path and could leave nuclei-templates@sha on the same host)."""
    if not safe_path(path):
        raise ValueError(json.dumps({"error": "unsafe_template_path", "message": "file_path outside the template-path grammar",
                                     "actual": str(path)[:120], "allowed": TEMPLATE_PATH.pattern}))
    return str(path)


def raw_url(sha: str, path: str) -> str:
    """The raw bytes of `path` AT commit `sha` (never a branch): the one builder of a template fetch URL."""
    if not SHA.fullmatch(sha or ""):
        raise ValueError(f"not a 40-hex commit SHA: {str(sha)[:50]!r}")
    return RAW_URL + sha + "/" + urllib.parse.quote(checked_path(path))


def parse_index(body: str, unsafe: list[str] | None = None) -> dict[str, str]:
    """cves.json (JSONL: {ID, Info, file_path}) → {CVE: file_path}. A row whose path fails `safe_path` is left out and
    appended to `unsafe` (the caller records the count on the index header)."""
    out: dict[str, str] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        cve, path = str(row.get("ID") or "").upper(), row.get("file_path")
        if not (re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve) and isinstance(path, str) and path.endswith((".yaml", ".yml"))):
            continue
        if not safe_path(path):
            if unsafe is not None:
                unsafe.append(f"{cve}: {path[:120]}")
            continue
        out[cve] = path
    return out


def _sync_index(store: Any, head: dict[str, Any], now: datetime, get_: Callable[[str], str], stats: dict[str, Any]) -> None:
    today = timeutil.iso(now)[:10]
    if head.get("checked_on") == today:
        return
    try:
        checksum = get_(CHECKSUM_URL).strip().split()[0].lower()
        if not re.fullmatch(r"[0-9a-f]{32}", checksum):
            raise ValueError(f"checksum file holds {checksum[:40]!r}, not an MD5")
        # re-read also when the shard count changed: rows written under the old count would be looked up in the wrong shard
        if checksum != head.get("checksum") or head.get("shards") != Limits.POC_INDEX_SHARDS:
            body = get_(INDEX_URL)
            got = hashlib.md5(body.encode(), usedforsecurity=False).hexdigest()
            if got != checksum:
                raise ValueError(f"cves.json MD5 {got} ≠ checksum {checksum} (torn read between two files on main)")
            unsafe: list[str] = []
            index = parse_index(body, unsafe)
            shards: dict[str, dict[str, str]] = {f"{INDEX_KEY}#{i}": {} for i in range(Limits.POC_INDEX_SHARDS)}
            for cve, path in index.items():
                shards[_index_shard(cve)][cve] = path
            for key, row in shards.items():   # all sizes checked before the first put: never a half-written index
                _check_size(key, row)
            for key, row in shards.items():
                _put(store, key, row)
            head.update({"checksum": checksum, "fetched_at": timeutil.iso(now), "count": len(index), "shards": Limits.POC_INDEX_SHARDS,
                         "unsafe_paths": {"n": len(unsafe), "sample": unsafe[:5]}})
            if unsafe:   # rows left out of the index are a degradation of the source, not "no template"
                stats["poc_degraded"] = f"index: {len(unsafe)} unsafe file_path rows left out, e.g. {unsafe[0]}"
        head.update({"checked_on": today, "error": None})
    except Exception as e:   # noqa: BLE001 — any failure: keep yesterday's index, visibly (head.error + stats)
        head["error"] = {"at": timeutil.iso(now), "error": str(e)[:300]}
        stats["poc_degraded"] = f"index: {str(e)[:200]}"
        log.warning(json.dumps({"station": "mitigate", "degraded": "poc_index_unavailable", "error": str(e)[:200]}))


def _lookup_budget(head: dict[str, Any], now: datetime) -> int:
    hour = timeutil.iso(now)[:13]
    lk = head.get("lookups") or {}
    used = lk.get("n", 0) if lk.get("hour") == hour else 0
    return max(0, min(Limits.POC_LOOKUPS_PER_RUN, Limits.POC_LOOKUPS_PER_HOUR - used))


def _spend(head: dict[str, Any], now: datetime) -> None:
    hour = timeutil.iso(now)[:13]
    lk = head.get("lookups") or {}
    head["lookups"] = {"hour": hour, "n": (lk.get("n", 0) if lk.get("hour") == hour else 0) + 1}


def _due(m: dict[str, Any] | None, path: str, now: datetime) -> bool:
    if not m or m.get("path") != path or m.get("state") not in ("found", "too_large"):
        return True
    t = timeutil.parse(m.get("checked_at") or "")
    return t is None or now - t >= timedelta(days=Limits.POC_RECHECK_DAYS)


def refresh(store: Any, cves: list[str], now: datetime, get_: Callable[[str], str] = get,
            clock: Callable[[], float] = time.monotonic, stats: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    """Bring the index and the pinned templates of `cves` up to date (within the lookup budget) and return, per CVE,
    {state, path, sha, text?, checked_at, error?} — `text` only for state found."""
    stats = stats if stats is not None else {}
    head = store.get_source_state(INDEX_KEY)
    _sync_index(store, head, now, get_, stats)
    want = sorted({c.upper() for c in cves if c})
    index: dict[str, str] = {}
    for part in store.get_source_states(sorted({_index_shard(c) for c in want})).values():
        index.update(part or {})
    meta: dict[str, dict[str, Any]] = {}
    for part in store.get_source_states(sorted({_meta_shard(c) for c in want})).values():
        meta.update(part or {})
    changed: set[str] = set()
    nowi = timeutil.iso(now)
    have_index = bool(head.get("checksum"))
    budget, start, tried, unsafe_n = _lookup_budget(head, now), clock(), 0, 0
    due = [c for c in want if c in index and _due(meta.get(c), index[c], now)]
    for c in want:
        if c not in index:
            st = "no_template" if have_index else "unavailable"
            if (meta.get(c) or {}).get("state") != st:
                meta[c] = {"state": st, "path": None, "sha": None, "checked_at": nowi}
                changed.add(c)
    for c in due:
        path, old = index[c], meta.get(c) or {}
        if not safe_path(path):   # an index row stored before the path gate existed: never fetched, never linked
            meta[c] = {"state": "error", "path": None, "sha": None, "checked_at": nowi,
                       "error": f"unsafe file_path in the index: {str(path)[:120]!r}"}
            changed.add(c)
            stats["poc_degraded"] = f"{c}: unsafe file_path in the index"
            unsafe_n += 1
            continue
        if tried >= budget or clock() - start > Limits.POC_BUDGET_S:
            break
        tried += 1
        try:
            _spend(head, now)
            commits = json.loads(get_(COMMITS_URL + urllib.parse.quote(checked_path(path))))
            sha = str((commits[0] if commits else {}).get("sha") or "")
            if not SHA.fullmatch(sha):
                raise ValueError(f"commits API gave no commit SHA for {path}")
            if sha == old.get("sha") and old.get("path") == path and old.get("state") in ("found", "too_large"):
                meta[c] = {**old, "checked_at": nowi, "error": None}
            else:
                text = get_(raw_url(sha, path))
                size = len(text.encode())
                if size > Limits.POC_TEMPLATE_MAX_BYTES:
                    meta[c] = {"state": "too_large", "path": path, "sha": sha, "checked_at": nowi, "bytes": size,
                               "error": f"template is {size} bytes, limit {Limits.POC_TEMPLATE_MAX_BYTES}"}
                else:
                    _put(store, TPL_KEY + c, {"sha": sha, "path": path, "text": text})
                    meta[c] = {"state": "found", "path": path, "sha": sha, "checked_at": nowi, "bytes": size, "error": None}
            changed.add(c)
        except Exception as e:   # noqa: BLE001 — one CVE without a fresh template this run; old pin kept, failure recorded
            meta[c] = {**old, "state": old.get("state") if old.get("state") == "found" else "error", "path": path,
                       "sha": old.get("sha"), "checked_at": old.get("checked_at") or nowi, "error": str(e)[:300]}
            changed.add(c)
            stats["poc_failed"] = stats.get("poc_failed", 0) + 1
            stats["poc_degraded"] = f"{c}: {str(e)[:200]}"
            log.warning(json.dumps({"station": "mitigate", "degraded": "poc_template_unavailable", "cve": c, "error": str(e)[:200]}))
    stats["poc_backlog"] = len(due) - tried - unsafe_n
    _put(store, INDEX_KEY, head)
    if changed:
        led: dict[str, dict[str, Any]] = {}
        shards = sorted({_meta_shard(c) for c in changed})
        for key, part in store.get_source_states(shards).items():
            led[key] = dict(part or {})
        for c in changed:
            led[_meta_shard(c)][c] = meta[c]
        for key, row in led.items():
            _put(store, key, row)
    found = [c for c in want if (meta.get(c) or {}).get("state") == "found"]
    texts = store.get_source_states([TPL_KEY + c for c in found]) if found else {}
    out: dict[str, dict[str, Any]] = {}
    for c in want:
        m = dict(meta.get(c) or {"state": "unavailable" if not have_index else "no_template", "path": None, "sha": None})
        if m.get("state") == "found":
            row = texts.get(TPL_KEY + c) or {}
            if row.get("sha") == m.get("sha"):
                m["text"] = row.get("text")
            else:   # the meta row says found but the template row is missing / older: say so, never use another pin
                m.update({"state": "error", "error": "template row missing or not at the pinned SHA"})
        out[c] = m
    return out


def template_url(sha: str, path: str) -> str:
    """Where a reader checks a quote: the file AT the pinned commit (github.com blob view) — path gated like raw_url."""
    if not SHA.fullmatch(sha or ""):
        raise ValueError(f"not a 40-hex commit SHA: {str(sha)[:50]!r}")
    return f"https://github.com/{REPO}/blob/{sha}/{urllib.parse.quote(checked_path(path))}"
