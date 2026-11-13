"""Item 5: the wall shows how an incident is being followed — a compact per-event summary in events.json built from the
on-chain case (radar.onchain) and the attack-tx case (radar.attacktx). Code only; absent cases ⇒ no line, not zeros."""
from radar import attacktx, insights, onchain
from radar.store import MemoryStore

EID = "ev_0a4e5c3e0fce8be9"


def _store():
    s = MemoryStore()
    v, r = "0x" + "1" * 40, "0x" + "2" * 40
    s.put_source_state(onchain.case_key(EID), {
        "victims": {"ethereum": {v: "Binance 热钱包"}}, "receivers": {r: {"chain": "ethereum", "label": "接收地址 1"}}, "evidence": {}, "attackers": {},
        "short": [], "delegation": {}, "cursors": {}, "window": ["2026-10-29T17:00:00Z", "2026-10-31T00:00:00Z"], "errors": [],
        "rows": [{"kind": "outflow", "t": "2026-10-29T20:24:23Z", "id": "a", "from": v, "to": r, "token": "USDT", "amount": 1.0},
                 {"kind": "outflow", "t": "2026-10-30T01:29:20Z", "id": "b", "from": r, "to": "0x" + "3" * 40, "token": "ETH", "amount": 2.0}],
        "freezes": [{"kind": "freeze", "t": "2026-10-30T00:14:50Z", "id": "f", "address": r, "chain": "ethereum", "issuer": "Tether"},
                    {"kind": "freeze", "t": "2026-10-30T03:00:00Z", "id": "g", "address": "0x" + "9" * 40, "chain": "ethereum",
                     "issuer": "Tether"}]})                                       # g: a wallet this case does not follow
    s.put_source_state(attacktx.case_key(EID), {"txs": {"0xaa": {"receipt": {"status": "0x1"}, "t": "2026-10-29T20:20:00Z"},
                                                        "0xbb": {"chain": "ethereum"}}})          # not decoded yet
    return s


def test_the_followup_line_counts_moves_freezes_and_decoded_attack_txs():
    f = insights.followup(_store(), EID)
    assert f == {"onchain_moves": 2, "freezes": 1, "attack_txs": 1, "last_at": "2026-10-30T01:29:20Z"}   # as the detail page


def test_an_event_nobody_follows_on_chain_has_no_followup():
    assert insights.followup(MemoryStore(), EID) is None


def test_the_followup_validates_against_the_schema():
    import json
    from pathlib import Path

    import jsonschema
    schema = json.loads((Path(__file__).parents[1] / "schemas" / "site-data.schema.json").read_text())
    jsonschema.validate(insights.followup(_store(), EID), {"$ref": "#/$defs/Followup", "$defs": schema["$defs"]})
