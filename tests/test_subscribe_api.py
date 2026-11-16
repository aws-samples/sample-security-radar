"""R7.3 — a token holder with radar/subscribe registers its own webhook; it sees and deletes only its own."""
import json
from datetime import UTC, datetime

import pytest

from radar import fetch, notify, subscribe_api
from radar.limits import Limits

NOW = datetime(2026, 11, 14, 6, 0, tzinfo=UTC)


class Box:
    def __init__(self, doc=None):
        self.doc, self.saves = doc or {}, 0

    def load(self):
        return json.loads(json.dumps(self.doc))

    def save(self, doc):
        self.doc, self.saves = json.loads(json.dumps(doc)), self.saves + 1


# names resolve without the network: *.rebind.example → 10.0.0.5 (an x.nip.io-style name), everything else public
_ADDRS = {"hooks.rebind.example": "10.0.0.5", "meta.rebind.example": "169.254.169.254"}


@pytest.fixture(autouse=True)
def _dns(monkeypatch):
    real = fetch.socket.getaddrinfo
    monkeypatch.setattr(fetch.socket, "getaddrinfo", lambda h, *a, **k: real(h, *a, **k) if str(h)[:1].isdigit()
                        else [(2, 1, 6, "", (_ADDRS.get(h, "93.184.215.14"), 0))])


def call(box, method, client="clienta0000000000000000001", scope="radar/read radar/subscribe", body=None, sid=None, status=None):
    ev = {"httpMethod": method, "body": json.dumps(body) if body is not None else None, "pathParameters": {"id": sid} if sid else None,
          "requestContext": {"authorizer": {"claims": {"scope": scope, "client_id": client}}}}
    r = subscribe_api.handler(ev, load=box.load, save=box.save, now=lambda: NOW, status=status or dict)
    return r["statusCode"], json.loads(r["body"])


def test_a_subscription_is_created_with_a_secret_shown_once_and_parses_for_the_station():
    box = Box()
    st, got = call(box, "POST", body={"target": "https://hooks.example.com/radar", "filters": {"severity": ["P0"], "min_loss_usd": 1e6}})
    assert st == 201 and got["id"] == "s-clienta000000000-1" and len(got["secret"]) >= 40 and got["created_at"] == "2026-11-14T06:00:00Z"
    [row] = box.doc["subscriptions"]
    assert row["owner"] is False and row["owner_client"].startswith("clienta") and row["secret"] == got["secret"]
    st, listed = call(box, "GET")
    assert st == 200 and listed["subscriptions"] == [{**{k: got[k] for k in ("id", "channel", "target", "filters", "created_at")},
                                                      "delivery": {"state": "not_run_yet", "at": None}}]
    assert "secret" not in json.dumps(listed)                                 # only the creation answer carries it
    conf = notify.parse_config(subscribe_api.merge({"rollout": "all", "subscriptions": []}, box.doc))
    assert [s.id for s in conf.subscriptions] == [got["id"]] and conf.invalid == [] and conf.subscriptions[0].owner is False


def test_a_client_sees_and_deletes_only_its_own():
    box = Box()
    _, a = call(box, "POST", body={"target": "https://a.example.com/h"})
    _, b = call(box, "POST", client="clientb0000000000000000002", body={"target": "https://b.example.com/h"})
    assert call(box, "GET", client="clientb0000000000000000002")[1]["subscriptions"][0]["id"] == b["id"]
    st, err = call(box, "DELETE", client="clientb0000000000000000002", sid=a["id"])
    assert st == 404 and err["error"] == "not_found" and len(box.doc["subscriptions"]) == 2      # another's is "not found"
    assert call(box, "DELETE", sid=a["id"]) == (200, {"deleted": a["id"]})
    assert [s["id"] for s in box.doc["subscriptions"]] == [b["id"]]


@pytest.mark.parametrize(("target", "code"), [
    ("http://hooks.example.com/x", "target_not_https"), ("https://10.0.0.5/x", "target_is_ip"),
    ("https://[::1]/x", "target_is_ip"), ("https://169.254.169.254/latest", "target_is_ip"),
    ("https://localhost/x", "target_not_public_name"), ("https://intranet/x", "target_not_public_name"),
    ("https://db.internal/x", "target_not_public_name"), ("https://user:pw@hooks.example.com/x", "target_has_credentials"),
    ("https://hooks.example.com:8443/x", "target_port"), ("https://hooks.example.com/x\n", "target_not_url"),
    ("", "target_not_url"), (None, "target_not_url"), ("https://" + "a" * 300 + ".example.com/", "target_not_url"),
    # a public-looking name resolving to a private / metadata address (surface review F1)
    ("https://hooks.rebind.example/x", "target_not_public"), ("https://meta.rebind.example/x", "target_not_public"),
])
def test_an_address_the_radar_will_not_post_to_is_refused_and_nothing_is_stored(target, code):
    box = Box()
    st, err = call(box, "POST", body={"target": target})
    assert st == 400 and err["error"] == code and box.saves == 0


@pytest.mark.parametrize(("kw", "status", "code"), [
    ({"scope": "radar/read"}, 403, "scope_missing"),                            # the read scope does not write
    ({"scope": "radar/subscribers"}, 403, "scope_missing"),
    ({"client": ""}, 403, "scope_missing"),                                     # no identity to own the row
    ({"body": {"target": "https://h.example.com/x", "owner": True}}, 400, "bad_body"),
    ({"body": {"target": "https://h.example.com/x", "filters": {"severity": ["P9"]}}}, 400, "filter_value"),
    ({"body": ["https://h.example.com/x"]}, 400, "bad_body"),
])
def test_everything_else_is_refused_with_a_code(kw, status, code):
    box = Box()
    st, err = call(box, "POST", **{"body": {"target": "https://h.example.com/x"}, **kw})
    assert (st, err["error"]) == (status, code) and box.saves == 0


def test_the_per_client_and_total_caps_hold():
    box = Box()
    for n in range(Limits.SELF_SUBSCRIPTIONS_PER_CLIENT):
        assert call(box, "POST", body={"target": f"https://h{n}.example.com/x"})[0] == 201
    st, err = call(box, "POST", body={"target": "https://more.example.com/x"})
    assert (st, err["error"], err["limit"]) == (409, "too_many_subscriptions", Limits.SELF_SUBSCRIPTIONS_PER_CLIENT)
    box.doc["subscriptions"] = [{"id": f"s-x-{n}", "owner_client": f"other{n}"} for n in range(Limits.SELF_SUBSCRIPTIONS_MAX)]
    assert call(box, "POST", body={"target": "https://more.example.com/x"})[1]["error"] == "subscriptions_full"
    assert Limits.SELF_SUBSCRIPTIONS_MAX < Limits.NOTIFY_SUBSCRIPTIONS_MAX


def test_a_stored_row_cannot_make_itself_an_owner_or_another_channel_or_shadow_the_operators():
    doc = {"subscriptions": [{"id": "ops", "channel": "webhook", "target": "https://evil.example.com/x", "secret": "k" * 40},
                             {"id": "s-a-1", "channel": "slack_dm", "owner": True, "target": "https://h.example.com/x", "secret": "k" * 40}]}
    merged = subscribe_api.merge({"rollout": "owner_only", "slack_bot_token": "xoxb-1",
                                  "subscriptions": [{"id": "ops", "owner": True, "channel": "slack_dm", "target": "U1"}]}, doc)
    conf = notify.parse_config(merged)
    by = {s.id: s for s in conf.subscriptions}
    assert by["ops"].channel == "slack_dm" and by["ops"].target == "U1"            # the operator's row wins the id …
    assert [i["error"] for i in conf.invalid] == ["duplicate_id"]                 # … and the other is reported
    assert by["s-a-1"].channel == "webhook" and by["s-a-1"].owner is False
    assert notify.gated(by["s-a-1"], conf.rollout) and not notify.gated(by["ops"], conf.rollout)   # rollout still decides


def test_unreadable_self_subscriptions_are_reported_not_silently_empty():
    conf = notify.parse_config({"rollout": "all", "subscriptions": [], "self_service_error": "AccessDenied"})
    assert [i["error"] for i in conf.invalid] == ["self_subscriptions_unreadable"]


# --- the consumer's command ---------------------------------------------------------------------------------------

def test_the_command_keeps_the_secret_in_a_private_file_and_never_prints_it(tmp_path, capsys):
    import stat

    from radar.agentkit import client, subscriptions
    sent = []

    def sender(method, path, body=None):
        sent.append((method, path, body))
        return {"id": "s-a-1", "target": body["target"], "secret": "S3CRET-VALUE"} if method == "POST" else {"subscriptions": []}
    assert subscriptions.main(["add", "--target", "https://h.example.com/x", "--filters", '{"severity": ["P0"]}'], sender, tmp_path) == 0
    out = capsys.readouterr().out
    assert "S3CRET-VALUE" not in out and json.loads(out)["secret_file"].endswith("webhook-s-a-1.secret")
    f = tmp_path / "webhook-s-a-1.secret"
    assert f.read_text() == "S3CRET-VALUE\n" and stat.S_IMODE(f.stat().st_mode) == 0o600
    assert sent == [("POST", "subscriptions", {"target": "https://h.example.com/x", "filters": {"severity": ["P0"]}})]
    assert subscriptions.main(["add", "--target", "https://h.example.com/x", "--filters", "{nope"], sender, tmp_path) == 1
    assert json.loads(capsys.readouterr().err)["error"] == "bad_filters"
    assert "subscriptions" not in " ".join(client.TOOLS) and subscriptions.SCOPE == subscribe_api.SCOPE   # not an agent tool


def test_a_subscriber_sees_whether_its_webhook_is_delivered_and_nothing_of_anyone_elses():
    """R8.7: registered behind the operator's owner_only switch, a subscription looked fine and received nothing."""
    box = Box()
    _, mine = call(box, "POST", body={"target": "https://a.example.com/h"})
    st = {"subscriptions": {mine["id"]: {"status": "gated_by_rollout", "at": "2026-11-14T06:05:00Z", "sent": 0},
                            "ops": {"status": "error", "error": {"error": "send_failed", "message": "https://secret.example/x"}}}}
    [row] = call(box, "GET", status=lambda: st)[1]["subscriptions"]
    assert row["delivery"] == {"state": "held_by_operator", "at": "2026-11-14T06:05:00Z", "sent_last_run": 0}
    st["subscriptions"][mine["id"]] = {"status": "error", "at": "x", "sent": 0, "error": {"error": "send_failed", "message": "https://a.example.com/h?k=1"}}
    [row] = call(box, "GET", status=lambda: st)[1]["subscriptions"]
    assert row["delivery"] == {"state": "failing", "at": "x", "sent_last_run": 0, "error": "send_failed"}
    assert "secret.example" not in json.dumps(row) and "k=1" not in json.dumps(row)          # codes only, never messages

    def broken():
        raise RuntimeError("AccessDenied")
    [row] = call(box, "GET", status=broken)[1]["subscriptions"]
    assert row["delivery"] == {"state": "unknown", "error": "RuntimeError"}                    # "could not read" ≠ "not delivering"


def test_the_status_read_is_one_item_of_the_table():
    from pathlib import Path
    stack = (Path(__file__).parents[1] / "infra" / "stack.py").read_text()
    assert '"dynamodb:LeadingKeys": ["SRC#__notify_status__"]' in stack and 'actions=["dynamodb:GetItem"], resources=[table.table_arn]' in stack
    from radar import notify_station
    assert subscribe_api.NOTIFY_STATUS_PK == f"SRC#{notify_station.STATUS_KEY}"
