"""R7 — agents read a deployed radar through one read-only client (CLI and stdio MCP are generated from one table).

Fixture: the UI mock site (ui/mock-data), i.e. documents of the published shape."""
import io
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from radar.agentkit import cli, client, mcp

SITE = Path(__file__).parents[1] / "ui" / "mock-data"
NOW = datetime(2026, 10, 23, 6, 0, tzinfo=UTC)


def reader(path):
    f = SITE / path
    if not f.is_file():
        raise client.RadarError("not_found", f"the radar answered HTTP 404 for {path}", 404, 200)
    return json.loads(f.read_text())


@pytest.fixture
def radar():
    return client.Radar(reader, lambda: NOW)


def test_recent_events_filter_and_say_how_many_matched(radar):
    every = radar.recent_events(limit=100)
    assert every["matched"] == every["returned"] == len(reader("data/events.json")["events"]) > 3
    ups = [e["last_updated"] for e in every["events"]]
    assert ups == sorted(ups, reverse=True)
    p0 = radar.recent_events(severity="P0", limit=100)
    assert 0 < p0["matched"] < every["matched"] and {e["severity"] for e in p0["events"]} == {"P0"}
    one = radar.recent_events(limit=1)
    assert one["returned"] == 1 and one["matched"] == every["matched"]          # a cut list says what it cut
    assert radar.recent_events(hours=1)["matched"] < every["matched"]


def test_an_event_and_its_rule_pack_are_read_by_id_and_absence_is_said(radar):
    eid = radar.recent_events(limit=1)["events"][0]["event_id"]
    assert radar.get_event(eid)["event"]["event_id"] == eid
    assert radar.rule_pack(eid) == {"event_id": eid, "available": False, "rule_pack": None}     # none ≠ an empty pack
    with_pack = client.Radar(lambda p: {**reader(p), "rule_pack": {"rules": [{"name": "r1"}]}}, lambda: NOW)
    assert with_pack.rule_pack(eid) == {"event_id": eid, "available": True, "rule_pack": {"rules": [{"name": "r1"}]}}


def test_search_matches_every_term_and_cve_status_says_unknown(radar):
    shard = reader("data/search/index.json")["months"][0]["month"]
    ev = reader(f"data/search/{shard}.json")["events"][0]
    word = ev["t"].split()[0]
    assert ev["id"] in [h["event_id"] for h in radar.search_events(word)["events"]]
    assert radar.search_events(f"{word} zzznotthere")["matched"] == 0
    assert radar.search_events(word, since="2999-01")["months_read"] == 0
    assert radar.cve_status("CVE-1999-0001") == {"cve": "CVE-1999-0001", "known": False, "events": []}


@pytest.mark.parametrize(("name", "args", "code"), [
    ("get_event", {"event_id": "../../ops"}, "bad_event_id"),          # an id is never a path
    ("get_event", {"event_id": "ev_abc\n"}, "bad_event_id"),
    ("recent_events", {"severity": "P9"}, "bad_severity"),
    ("recent_events", {"limit": 1000}, "bad_limit"),
    ("search_events", {"query": "  "}, "empty_query"),
    ("search_events", {}, "bad_arguments"),
    ("search_events", {"query": "x", "since": "2026-1"}, "bad_since"),
    ("cve_status", {"cve": "CVE-1"}, "bad_cve"),
    ("recent_events", {"drop_table": 1}, "bad_arguments"),
    ("delete_event", {}, "unknown_tool"),
])
def test_bad_input_is_refused_with_a_code_before_anything_is_read(name, args, code):
    def no_read(path):
        raise AssertionError(f"read {path}")
    with pytest.raises(client.RadarError) as e:
        client.call(client.Radar(no_read, lambda: NOW), name, args)
    assert e.value.detail["error"] == code and "limit" in e.value.detail


def test_every_tool_is_a_read_and_the_table_is_the_only_list():
    assert set(client.TOOLS) == {n for n in vars(client.Radar) if not n.startswith("_")}
    src = (Path(client.__file__)).read_text()
    # the one request with a body is the token exchange (fetch_token → _post); documents are only ever GET
    assert src.count("data=body") == 1 and "method=" not in src and ".put" not in src


def test_credentials_go_to_the_radar_only_over_https_and_never_follow_a_redirect():
    with pytest.raises(client.RadarError) as e:
        client.http_get({"RADAR_URL": "http://radar.example", "RADAR_TOKEN": "t"})
    assert e.value.detail["error"] == "bad_radar_url"
    client.http_get({"RADAR_URL": "http://127.0.0.1:8080"})                       # local development
    assert client._auth_header({"RADAR_TOKEN": "t", "RADAR_USER": "u", "RADAR_PASSWORD": "p"}) == {"Authorization": "Bearer t"}
    assert client._auth_header({"RADAR_USER": "u", "RADAR_PASSWORD": "p"})["Authorization"].startswith("Basic ")
    assert client._auth_header({"RADAR_USER": "u"}) == {}
    with pytest.raises(client.RadarError) as e:
        client._NoRedirect().redirect_request(None, None, 302, "", {}, "https://elsewhere.example/x")
    assert e.value.detail["error"] == "redirect_refused"


def test_the_cli_prints_one_json_document_and_fails_with_the_error(radar, capsys):
    assert cli.main(["recent_events", "--severity", "P0", "--limit", "2"], radar) == 0
    assert json.loads(capsys.readouterr().out)["returned"] <= 2
    assert cli.main(["get_event", "--event_id", "nope"], radar) == 1
    assert json.loads(capsys.readouterr().err)["error"] == "bad_event_id"
    assert cli.main(["--list"], radar) == 0 and set(json.loads(capsys.readouterr().out)) == set(client.TOOLS)


def _rpc(*msgs, radar=None):
    out = io.StringIO()
    mcp_handle = mcp.handle
    try:
        if radar is not None:
            mcp.handle = lambda m: mcp_handle(m, lambda: radar)
        mcp.serve(io.StringIO("".join(json.dumps(m) + "\n" if isinstance(m, dict) else m for m in msgs)), out)
    finally:
        mcp.handle = mcp_handle
    return [json.loads(ln) for ln in out.getvalue().splitlines()]


def test_the_mcp_server_lists_the_table_as_read_only_tools_and_answers_calls(radar):
    init, listed, got, bad, unknown = _rpc(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},                          # a notification: no answer
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "recent_events", "arguments": {"limit": 1}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "get_event", "arguments": {"event_id": "x"}}},
        {"jsonrpc": "2.0", "id": 5, "method": "resources/list"},
        radar=radar)
    assert init["result"]["protocolVersion"] == "2025-06-18" and init["result"]["capabilities"] == {"tools": {}}
    tools = listed["result"]["tools"]
    assert [t["name"] for t in tools] == list(client.TOOLS)
    assert all(t["annotations"]["readOnlyHint"] and t["inputSchema"]["additionalProperties"] is False for t in tools)
    assert got["result"]["isError"] is False and json.loads(got["result"]["content"][0]["text"])["returned"] == 1
    assert bad["result"]["isError"] is True and json.loads(bad["result"]["content"][0]["text"])["error"] == "bad_event_id"
    assert unknown["error"]["code"] == -32601


def test_a_line_that_is_not_json_gets_a_parse_error_and_the_server_goes_on(radar):
    err, pong = _rpc("{not json\n", {"jsonrpc": "2.0", "id": 9, "method": "ping"}, radar=radar)
    assert err["error"]["code"] == -32700 and pong == {"jsonrpc": "2.0", "id": 9, "result": {}}


def test_the_skill_and_llms_txt_name_exactly_the_tools_that_exist():
    root = Path(__file__).parents[1]
    skill = (root / "integrations/skill/security-radar/SKILL.md").read_text()
    llms = (root / "ui/public/llms.txt").read_text()
    for name in client.TOOLS:
        assert name in skill and name in llms, name
    import re
    assert set(re.findall(r"`radar ([a-z_]+)", skill)) <= set(client.TOOLS)


def test_an_open_site_is_read_with_no_credential_at_all(monkeypatch):
    """Neo 2026-11-16: reading is open by default — RADAR_URL alone, no token, no password; the documents come from the
    site's /data/ (not /api/, which needs a token)."""
    seen = {}

    class R:
        def read(self, n):
            return b'{"ok": true}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class Opener:
        def open(self, req, timeout):
            seen.update(url=req.full_url, auth=req.get_header("Authorization"))
            return R()
    monkeypatch.setattr(client.urllib.request, "build_opener", lambda *a: Opener())
    assert client.http_get({"RADAR_URL": "https://radar.example"})("data/events.json") == {"ok": True}
    assert seen == {"url": "https://radar.example/data/events.json", "auth": None}
