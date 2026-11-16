"""Offline AWS WAF matcher — the per-rule gate of the rule pack (docs/research/action/01-waf.md §5).

A rule enters a pack only if every positive sample matches and no negative sample does, evaluated HERE, offline,
in milliseconds, by a pure function. It mirrors the documented semantics of the statements the radar generates; what
it cannot reproduce faithfully (SqliMatch / XssMatch signatures, rate counters, managed groups — AWS does not publish
them) evaluates to None = "cannot tell offline", never to a guessed True/False. And / Or / Not combine with Kleene
three-valued logic, so a rule whose verdict depends on an unknown part is reported `unchecked`, not `pass`.

Semantics implemented, with the AWS documentation they come from:

* ByteMatchStatement — https://docs.aws.amazon.com/waf/latest/APIReference/API_ByteMatchStatement.html
  PositionalConstraint: EXACTLY "the value of the web request component is identical to SearchString"; STARTS_WITH
  "SearchString appears at the beginning"; ENDS_WITH "appears at the end"; CONTAINS "appears anywhere";
  CONTAINS_WORD "SearchString must contain only alphanumeric characters or underscore … is at the beginning of the
  specified part of the web request or is preceded by a character other than an alphanumeric character or underscore,
  and is at the end … or is followed by a character other than an alphanumeric character or underscore".
  SearchString is matched against the TRANSFORMED component ("if you use text transformations … specify the
  SearchString in the transformed form").
* RegexMatchStatement — https://docs.aws.amazon.com/waf/latest/APIReference/API_RegexMatchStatement.html — RE2 syntax,
  unanchored search. Python `re` stands in; constructs RE2 rejects (look-around, back-references) are refused here too
  (ValueError), so a pattern that passes offline is never one AWS would reject for syntax.
* SizeConstraintStatement — https://docs.aws.amazon.com/waf/latest/APIReference/API_SizeConstraintStatement.html —
  size in bytes of the transformed component compared with Size by ComparisonOperator (EQ NE LE LT GE GT).
* FieldToMatch — https://docs.aws.amazon.com/waf/latest/APIReference/API_FieldToMatch.html
  UriPath "the part of a web request that identifies a resource, for example, /images/daily-ad.jpg";
  QueryString "the part of a URL that appears after a ? character, if any"; SingleQueryArgument "name … isn't case
  sensitive"; SingleHeader "Provide the name of the header to inspect … This setting isn't case sensitive";
  Body: "AWS WAF can inspect only the first 8 KB (8,192 bytes)" for ALB / AppSync (CloudFront default 16 KB) —
  Limits.WAF_BODY_INSPECT_BYTES; OversizeHandling CONTINUE (inspect what is within the limit, the default) / MATCH /
  NO_MATCH. A header / query argument the request does not carry ⇒ the statement does not match [推断: AWS states this
  for SingleHeader; the same is assumed for SingleQueryArgument].
* TextTransformation — https://docs.aws.amazon.com/waf/latest/APIReference/API_TextTransformation.html
  "AWS WAF processes all transformations, from lowest priority to highest, before inspecting the transformed content.
  The priorities don't need to be consecutive, but they must all be different." Types implemented: NONE, URL_DECODE
  ("Decode a URL-encoded value" — %XX only; '+' is left as is [未验证]), HTML_ENTITY_DECODE (&quot; &nbsp; &lt; &gt;
  &amp; [推断], &#xhhhh; &#nnnn;), LOWERCASE ("Convert uppercase letters (A-Z) to lowercase (a-z)"),
  COMPRESS_WHITE_SPACE ("Replace these characters with a space character (decimal 32): \\f \\t \\n \\r \\v,
  non-breaking space (decimal 160). … also replaces multiple spaces with one space"), CMD_LINE ("Delete the following
  characters: \\ " ' ^ · Delete spaces before the following characters: / ( · Replace the following characters with a
  space: , ; · Replace multiple spaces with one space · Convert uppercase letters (A-Z) to lowercase (a-z)"),
  NORMALIZE_PATH ("Remove multiple slashes, directory self-references, and directory back-references that are not at
  the beginning of the input"). Any other type is refused (ValueError) — never silently skipped.

Known drift (01-waf §5.3): the matcher is calibrated against AWS only by the live replay (W11). Bodies are read as
latin-1 so every byte maps to one character, as AWS inspects bytes.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any

from radar.limits import Limits

Verdict = bool | None   # None = cannot be evaluated offline (signature / counter AWS does not publish)


@dataclass(frozen=True)
class Request:
    """One sample request as it reaches AWS WAF. `uri` is the request target as sent (path + optional ?query, raw)."""
    method: str = "GET"
    uri: str = "/"
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes = b""
    ip: str = "198.51.100.7"      # TEST-NET-2: a sample source address, never a real one

    @property
    def path(self) -> str:
        return self.uri.split("?", 1)[0]

    @property
    def query(self) -> str:
        return self.uri.split("?", 1)[1] if "?" in self.uri else ""

    def as_dict(self) -> dict[str, Any]:
        return {"method": self.method, "uri": self.uri, "headers": [list(h) for h in self.headers],
                "body": self.body.decode("latin-1")}


# ---------------------------------------------------------------- text transformations
_ENTITIES = {"quot": '"', "nbsp": "\xa0", "lt": "<", "gt": ">", "amp": "&"}
_ENTITY = re.compile(r"&(?:#[xX]([0-9a-fA-F]{1,6})|#(\d{1,7})|(quot|nbsp|lt|gt|amp));")


def _entity(m: re.Match[str]) -> str:
    try:
        if m.group(1):
            return chr(int(m.group(1), 16))
        if m.group(2):
            return chr(int(m.group(2)))
    except (ValueError, OverflowError):   # &#99999999; — out of Unicode range: left as written
        return m.group(0)
    return _ENTITIES[m.group(3)]


def _normalize_path(s: str) -> str:
    lead = len(s) - len(s.lstrip("/"))
    parts: list[str] = []
    for seg in re.sub(r"/{2,}", "/", s).split("/"):
        if seg == ".":
            continue
        if seg == ".." and parts and parts[-1] not in ("", ".."):
            parts.pop()
            continue
        parts.append(seg)
    out = "/".join(parts)
    return ("/" if lead and not out.startswith("/") else "") + out


def _cmd_line(s: str) -> str:
    s = re.sub(r"[\\\"'^]", "", s)
    s = re.sub(r" +(?=[/(])", "", s)
    s = re.sub(r"[,;]", " ", s)
    return re.sub(r" {2,}", " ", s).lower()


TRANSFORMS = {
    "NONE": lambda s: s,
    "URL_DECODE": lambda s: urllib.parse.unquote(s, encoding="latin-1"),
    "HTML_ENTITY_DECODE": lambda s: _ENTITY.sub(_entity, s),
    "LOWERCASE": lambda s: re.sub(r"[A-Z]+", lambda m: m.group(0).lower(), s),   # A-Z only, as documented
    "COMPRESS_WHITE_SPACE": lambda s: re.sub(r" {2,}", " ", re.sub(r"[\f\t\n\r\v\xa0]", " ", s)),
    "CMD_LINE": _cmd_line,
    "NORMALIZE_PATH": _normalize_path,
}


def transform(value: str, transformations: list[dict[str, Any]]) -> str:
    """Apply TextTransformations lowest Priority first. Duplicate priorities / unknown types ⇒ ValueError (AWS rejects
    the first; the second would be a silent no-op here and a different result at AWS)."""
    prios = [t["Priority"] for t in transformations]
    if len(set(prios)) != len(prios):
        raise ValueError(f"duplicate TextTransformation priorities {prios}")
    for t in sorted(transformations, key=lambda t: t["Priority"]):
        if t["Type"] not in TRANSFORMS:
            raise ValueError(f"TextTransformation {t['Type']!r} is not implemented offline")
        value = TRANSFORMS[t["Type"]](value)
    return value


# ---------------------------------------------------------------- field to match
_OVERSIZE = object()


def field(ftm: dict[str, Any], req: Request) -> str | None | object:
    """The raw component FieldToMatch selects; None = not present; _OVERSIZE = body over the inspection limit."""
    if len(ftm) != 1:
        raise ValueError(f"FieldToMatch must name exactly one component, got {sorted(ftm)}")
    kind, spec = next(iter(ftm.items()))
    if kind == "UriPath":
        return req.path
    if kind == "QueryString":
        return req.query
    if kind == "Method":
        return req.method
    if kind == "SingleHeader":
        want = spec["Name"].lower()
        vals = [v for n, v in req.headers if n.lower() == want]
        return vals[0] if vals else None
    if kind == "SingleQueryArgument":
        want = spec["Name"].lower()
        for part in req.query.split("&"):
            name, _, val = part.partition("=")
            if name.lower() == want:
                return val
        return None
    if kind == "Body":
        body = req.body.decode("latin-1")
        if len(req.body) > Limits.WAF_BODY_INSPECT_BYTES:
            mode = spec.get("OversizeHandling", "CONTINUE")
            if mode != "CONTINUE":
                return _OVERSIZE if mode == "MATCH" else None
            return body[: Limits.WAF_BODY_INSPECT_BYTES]
        return body
    raise ValueError(f"FieldToMatch {kind} is not implemented offline")


# ---------------------------------------------------------------- statements
_RE2_UNSUPPORTED = re.compile(r"\(\?[=!]|\(\?<[=!]|\\[1-9]|\(\?P=")
_WORD = re.compile(r"[A-Za-z0-9_]+")
_OPS = {"EQ": lambda a, b: a == b, "NE": lambda a, b: a != b, "LE": lambda a, b: a <= b, "LT": lambda a, b: a < b,
        "GE": lambda a, b: a >= b, "GT": lambda a, b: a > b}


def byte_match(value: str, search: str, positional: str) -> bool:
    if positional == "EXACTLY":
        return value == search
    if positional == "STARTS_WITH":
        return value.startswith(search)
    if positional == "ENDS_WITH":
        return value.endswith(search)
    if positional == "CONTAINS":
        return search in value
    if positional == "CONTAINS_WORD":
        if not _WORD.fullmatch(search):
            raise ValueError(f"CONTAINS_WORD needs an alphanumeric/underscore SearchString, got {search!r}")
        return re.search(rf"(?<![A-Za-z0-9_]){re.escape(search)}(?![A-Za-z0-9_])", value) is not None
    raise ValueError(f"PositionalConstraint {positional!r} is not one of AWS WAF's five")


def regex_ok(pattern: str) -> re.Pattern[str]:
    if _RE2_UNSUPPORTED.search(pattern):
        raise ValueError(f"regex {pattern!r} uses look-around or a back-reference — RE2 (AWS WAF) does not support it")
    return re.compile(pattern)


def match(stmt: dict[str, Any], req: Request, ip_sets: dict[str, list[str]] | None = None) -> Verdict:
    """True / False when this statement matches `req` under AWS WAF semantics; None when it cannot be told offline."""
    if len(stmt) != 1:
        raise ValueError(f"a Statement holds exactly one statement, got {sorted(stmt)}")
    kind, s = next(iter(stmt.items()))
    if kind == "AndStatement":
        vals = [match(x, req, ip_sets) for x in s["Statements"]]
        return False if False in vals else (None if None in vals else True)
    if kind == "OrStatement":
        vals = [match(x, req, ip_sets) for x in s["Statements"]]
        return True if True in vals else (None if None in vals else False)
    if kind == "NotStatement":
        v = match(s["Statement"], req, ip_sets)
        return None if v is None else not v
    if kind in ("SqliMatchStatement", "XssMatchStatement", "RateBasedStatement", "ManagedRuleGroupStatement",
                "RuleGroupReferenceStatement"):
        return None   # signature / counter not public — the live replay calibrates these, the matcher does not guess
    if kind == "IPSetReferenceStatement":
        cidrs = (ip_sets or {}).get(s["ARN"])
        if cidrs is None:
            return None
        addr = ipaddress.ip_address(req.ip)
        return any(addr in ipaddress.ip_network(c, strict=False) for c in cidrs)
    raw = field(s["FieldToMatch"], req)
    if raw is _OVERSIZE:
        return True
    if raw is None:
        return False
    if not isinstance(raw, str):        # was an assert (gone under python -O): a non-text field is a bug, said loudly
        raise TypeError(f"field value must be text, got {type(raw).__name__}")
    value = transform(raw, s.get("TextTransformations") or [{"Priority": 0, "Type": "NONE"}])
    if kind == "ByteMatchStatement":
        search = s["SearchString"]
        if len(search.encode()) > Limits.WAF_SEARCH_STRING_MAX:
            raise ValueError(f"SearchString is {len(search.encode())} bytes, AWS allows {Limits.WAF_SEARCH_STRING_MAX}")
        return byte_match(value, search, s["PositionalConstraint"])
    if kind == "RegexMatchStatement":
        return regex_ok(s["RegexString"]).search(value) is not None
    if kind == "SizeConstraintStatement":
        return _OPS[s["ComparisonOperator"]](len(value.encode("latin-1", "replace")), int(s["Size"]))
    raise ValueError(f"statement {kind} is not implemented offline")


def gate(stmt: dict[str, Any], positives: list[Request], negatives: list[Request],
         ip_sets: dict[str, list[str]] | None = None) -> dict[str, Any]:
    """The rule-pack gate: pass = every positive matches and no negative does; fail = the first sample that breaks it
    (machine reason + which sample); unchecked = no sample contradicts, but a part could not be evaluated offline."""
    if not positives or not negatives:
        return {"state": "fail", "reason": "no_samples", "detail": "a rule needs ≥ 1 positive and ≥ 1 negative sample"}
    unknown = False
    for i, r in enumerate(positives):
        v = match(stmt, r, ip_sets)
        if v is False:
            return {"state": "fail", "reason": "positive_missed", "sample": i, "detail": f"正样本 {i} 未命中：{r.method} {r.uri[:120]}"}
        unknown |= v is None
    for i, r in enumerate(negatives):
        v = match(stmt, r, ip_sets)
        if v is True:
            return {"state": "fail", "reason": "negative_matched", "sample": i, "detail": f"负样本 {i} 被命中：{r.method} {r.uri[:120]}"}
        unknown |= v is None
    if unknown:
        return {"state": "unchecked", "reason": "signature_not_offline",
                "detail": "SqliMatch / XssMatch / 速率 / 托管组的签名由 AWS 维护，离线无法判定；样本未与可判定部分矛盾"}
    return {"state": "pass", "reason": "samples_agree", "detail": f"{len(positives)} 个正样本全中、{len(negatives)} 个负样本全不中"}
