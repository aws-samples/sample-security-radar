"""The offline AWS WAF matcher (radar.wafmatch): table-driven against the documented semantics it cites."""

import pytest

from radar.limits import Limits
from radar.wafmatch import Request, gate, match, transform


def _bm(search: str, pos: str, ftm: dict, tts: list[tuple[int, str]] = ((0, "NONE"),)) -> dict:
    return {"ByteMatchStatement": {"SearchString": search, "PositionalConstraint": pos, "FieldToMatch": ftm,
                                   "TextTransformations": [{"Priority": p, "Type": t} for p, t in tts]}}


URI = {"UriPath": {}}

# (value of the UriPath, SearchString, PositionalConstraint, expected) — the five constraints of API_ByteMatchStatement
POSITIONAL = [
    ("/admin", "/admin", "EXACTLY", True), ("/admin/", "/admin", "EXACTLY", False),
    ("/admin/x", "/admin", "STARTS_WITH", True), ("/x/admin", "/admin", "STARTS_WITH", False),
    ("/x/welcome.cgi", "/welcome.cgi", "ENDS_WITH", True), ("/welcome.cgi/x", "/welcome.cgi", "ENDS_WITH", False),
    ("/a/../b", "../", "CONTAINS", True), ("/a/b", "../", "CONTAINS", False),
    ("/x;BadBot", "BadBot", "CONTAINS_WORD", True), ("/BadBot;", "BadBot", "CONTAINS_WORD", True),
    ("/-BadBot;", "BadBot", "CONTAINS_WORD", True), ("/BadBots", "BadBot", "CONTAINS_WORD", False),
    ("/x_BadBot", "BadBot", "CONTAINS_WORD", False), ("BadBot", "BadBot", "CONTAINS_WORD", True),
]


@pytest.mark.parametrize("path,search,pos,want", POSITIONAL)
def test_byte_match_positional_constraints(path, search, pos, want):
    assert match(_bm(search, pos, URI), Request(uri=path)) is want


def test_contains_word_refuses_a_non_word_search_string():
    with pytest.raises(ValueError):
        match(_bm("../", "CONTAINS_WORD", URI), Request(uri="/a"))


# (raw, transformations, expected) — API_TextTransformation, applied lowest priority first
TRANSFORM_CASES = [
    ("%252e%252e%252f", [(0, "URL_DECODE")], "%2e%2e%2f"),
    ("%252e%252e%252f", [(0, "URL_DECODE"), (1, "URL_DECODE")], "../"),
    ("a+b%20c", [(0, "URL_DECODE")], "a+b c"),
    ("&lt;script&gt;&#x41;&#66;&quot;&nbsp;", [(0, "HTML_ENTITY_DECODE")], '<script>AB"\xa0'),
    ("SeLeCt ÄB", [(0, "LOWERCASE")], "select Äb"),
    ("a\t\n\r\f\vb   c\xa0d", [(0, "COMPRESS_WHITE_SPACE")], "a b c d"),
    ("C:\\Win\"dows\\ ^sys'tem /c ,dir;  X", [(0, "CMD_LINE")], "c:windows system/c dir x"),
    ("/a//b/./c/../d", [(0, "NORMALIZE_PATH")], "/a/b/d"),
    # priority order, not list order: LOWERCASE(0) then URL_DECODE(5) leaves the decoded %41 upper case
    ("%41b", [(5, "URL_DECODE"), (0, "LOWERCASE")], "Ab"),
    ("%41b", [(0, "URL_DECODE"), (5, "LOWERCASE")], "ab"),
]


@pytest.mark.parametrize("raw,tts,want", TRANSFORM_CASES)
def test_text_transformations(raw, tts, want):
    assert transform(raw, [{"Priority": p, "Type": t} for p, t in tts]) == want


def test_transformations_change_the_verdict():
    """The point of transforms: a double-encoded traversal is invisible without them and caught with them."""
    req = Request(uri="/?pagename=templates%252f%252e%252e%252f%252e%252e%252fwp-config")
    arg = {"SingleQueryArgument": {"Name": "pagename"}}
    assert match(_bm("../", "CONTAINS", arg), req) is False
    assert match(_bm("../", "CONTAINS", arg, [(0, "URL_DECODE"), (1, "URL_DECODE")]), req) is True


def test_unknown_transform_and_duplicate_priority_are_refused():
    with pytest.raises(ValueError):
        transform("x", [{"Priority": 0, "Type": "BASE64_DECODE"}])
    with pytest.raises(ValueError):
        transform("x", [{"Priority": 0, "Type": "LOWERCASE"}, {"Priority": 0, "Type": "URL_DECODE"}])


def test_fields_to_match():
    req = Request("POST", "/p/a?Path=http%3A%2F%2Fx&q=1", (("X-DSCGI-Path", "/x"), ("Host", "h")), b"<a>1</a>")
    assert match(_bm("/p/a", "EXACTLY", URI), req) is True
    assert match(_bm("Path=http%3A%2F%2Fx&q=1", "EXACTLY", {"QueryString": {}}), req) is True
    # names are case-insensitive for SingleHeader and SingleQueryArgument
    assert match(_bm("/x", "EXACTLY", {"SingleHeader": {"Name": "x-dscgi-path"}}), req) is True
    assert match(_bm("http://x", "EXACTLY", {"SingleQueryArgument": {"Name": "path"}}, [(0, "URL_DECODE")]), req) is True
    assert match(_bm("<a>", "CONTAINS", {"Body": {}}), req) is True
    # absent header / argument ⇒ no match
    assert match(_bm("", "CONTAINS", {"SingleHeader": {"Name": "x-absent"}}), req) is False
    assert match(_bm("", "CONTAINS", {"SingleQueryArgument": {"Name": "absent"}}), req) is False


def test_body_beyond_the_inspection_limit_is_invisible_unless_oversize_says_otherwise():
    body = b"a" * Limits.WAF_BODY_INSPECT_BYTES + b"EVIL"
    req = Request("POST", "/", (), body)
    assert match(_bm("EVIL", "CONTAINS", {"Body": {}}), req) is False                                  # CONTINUE (default)
    assert match(_bm("EVIL", "CONTAINS", {"Body": {"OversizeHandling": "MATCH"}}), req) is True
    assert match(_bm("EVIL", "CONTAINS", {"Body": {"OversizeHandling": "NO_MATCH"}}), req) is False
    assert match(_bm("EVIL", "CONTAINS", {"Body": {}}), Request("POST", "/", (), b"EVIL")) is True


def test_regex_size_and_logic():
    rx = {"RegexMatchStatement": {"RegexString": "^(https?|ftp|gopher|file)://", "FieldToMatch": {"SingleQueryArgument": {"Name": "path"}},
                                  "TextTransformations": [{"Priority": 0, "Type": "URL_DECODE"}, {"Priority": 1, "Type": "LOWERCASE"}]}}
    assert match(rx, Request(uri="/v?path=HTTP%3A%2F%2Fevil")) is True
    assert match(rx, Request(uri="/v?path=/library/1")) is False
    with pytest.raises(ValueError):   # RE2 has no look-around
        match({"RegexMatchStatement": {**rx["RegexMatchStatement"], "RegexString": "(?=a)b"}}, Request(uri="/?path=a"))
    size = {"SizeConstraintStatement": {"FieldToMatch": {"SingleHeader": {"Name": "x-a"}}, "ComparisonOperator": "GT", "Size": 0,
                                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}
    assert match(size, Request(headers=(("X-A", "1"),))) is True
    assert match(size, Request()) is False
    sqli = {"SqliMatchStatement": {"FieldToMatch": {"Body": {}}, "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}
    t, f = _bm("/", "STARTS_WITH", URI), _bm("/nope", "EXACTLY", URI)
    assert match({"AndStatement": {"Statements": [t, sqli]}}, Request()) is None       # Kleene: unknown
    assert match({"AndStatement": {"Statements": [f, sqli]}}, Request()) is False
    assert match({"OrStatement": {"Statements": [t, sqli]}}, Request()) is True
    assert match({"NotStatement": {"Statement": f}}, Request()) is True


def test_gate_states():
    rule = _bm("/access/api/v1/aws/token/", "EXACTLY", URI, [(0, "URL_DECODE")])
    pos, neg = [Request("POST", "/access/api/v1/aws/token/"), Request("POST", "/access/api/v1/aws/token%2F")], \
        [Request("POST", "/access/api/v1/aws/token")]
    assert gate(rule, pos, neg)["state"] == "pass"
    assert gate(rule, neg, pos)["reason"] == "positive_missed"
    assert gate(rule, pos, pos)["reason"] == "negative_matched"
    assert gate(rule, pos, [])["reason"] == "no_samples"
    sqli = {"AndStatement": {"Statements": [rule, {"SqliMatchStatement": {"FieldToMatch": {"Body": {}},
                                                                            "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}]}}
    assert gate(sqli, pos, neg)["state"] == "unchecked"
