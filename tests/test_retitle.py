"""Root-cause title correction (Neo 2026-11-02): an event's title comes from the first structured record and is never
rewritten by a later hypothesis — so when the cause becomes clear (Binance: "Key Leaked via Infrastructure" vs Binance's
own "no evidence of any wallet private key leak … compromised DevOps engineer's laptop"), an operator corrects it with
their own IAM credentials, citing the source. Shown on the page as a correction, original kept."""
from datetime import UTC, datetime

import pytest

from radar import publish, retitle
from radar.model import Event
from radar.store import MemoryStore

NOW = datetime(2026, 11, 2, 5, tzinfo=UTC)
EID = "ev_0a4e5c3e0fce8be9"
SRC = "https://www.euronews.com/2026/10/30/how-the-binance-hack-happened-and-who-was-behind-it"


def store():
    s = MemoryStore()
    s.put_event(Event(event_id=EID, domain="web3", title="Binance CEX — Key Leaked via Infrastructure",
                      first_seen="2026-10-29T20:51:50Z", last_updated="2026-11-01T00:00:00Z", item_ids=[], keys=[], severity="P0"))
    return s


@pytest.mark.parametrize(("eid", "title", "source", "code"), [
    (EID + "\n", "X", SRC, "bad_event_id"),
    ("ev_ffffffffffffffff", "X", SRC, "unknown_event"),
    (EID, "", SRC, "bad_title"),
    (EID, "x" * 161, SRC, "bad_title"),
    (EID, "Binance CEX — Unauthorized Withdrawals", "", "bad_source"),
    (EID, "Binance CEX — Unauthorized Withdrawals", "javascript:alert(1)", "bad_source"),
])
def test_bad_input_is_refused_with_the_four_part_error(eid, title, source, code):
    with pytest.raises(retitle.RetitleError) as e:
        retitle.set_title(store(), eid, title, source, "", "operator", NOW)
    assert e.value.detail["error"] == code and {"message", "actual", "limit"} <= e.value.detail.keys()


def test_the_corrected_title_is_published_with_its_source_and_the_original():
    s = store()
    retitle.set_title(s, EID, "Binance CEX — Unauthorized Withdrawals via Compromised DevOps Laptop", SRC,
                      "币安官方：未发现私钥泄露", "operator", NOW)
    assert retitle.changed(s) == [EID] and retitle.changed(s) == []
    listing, _ = publish.events_doc(s, NOW)
    [row] = listing["events"]
    assert row["title"] == "Binance CEX — Unauthorized Withdrawals via Compromised DevOps Laptop"
    assert row["title_override"] == {"title": row["title"], "original": "Binance CEX — Key Leaked via Infrastructure",
                                     "source": SRC, "note": "币安官方：未发现私钥泄露", "by": "operator", "at": "2026-11-02T05:00:00Z"}
    detail = publish.event_doc(s.get_event(EID), s, NOW)
    assert detail["event"]["title"] == row["title"]


def test_an_event_without_a_correction_keeps_its_structured_title():
    listing, _ = publish.events_doc(store(), NOW)
    [row] = listing["events"]
    assert row["title"] == "Binance CEX — Key Leaked via Infrastructure" and row.get("title_override") is None


def test_the_published_override_validates_against_the_schema():
    import json
    from pathlib import Path

    import jsonschema
    s = store()
    retitle.set_title(s, EID, "Binance CEX — Unauthorized Withdrawals", SRC, "", "operator", NOW)
    schema = json.loads((Path(__file__).parents[1] / "schemas" / "site-data.schema.json").read_text())
    [row] = publish.events_doc(s, NOW)[0]["events"]
    jsonschema.validate(row["title_override"], {"$ref": "#/$defs/TitleOverride", "$defs": schema["$defs"]})
