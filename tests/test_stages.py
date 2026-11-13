"""The one attack-stage enum (radar.stages, P1b / 04-reconstruction W1, W5). Before it the M4 phase enum had four hand
copies and no test pinning them together (B7); the cloud kill chain did not exist (§0.3); on-chain freezes did not count
as evidence, so the flow listed 「尚无报道的阶段：冻结」 next to a table of issuer freezes (B8)."""
import importlib.util
import json
from pathlib import Path

import jsonschema
import pytest

from radar import stages

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas" / "site-data.schema.json").read_text())


def _gen():
    spec = importlib.util.spec_from_file_location("gen_stages", ROOT / "scripts" / "gen_stages.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── single source ─────────────────────────────────────────────────────────────────────────────────────────────────────

def test_the_schema_enum_and_the_ui_table_are_generated_from_stages():
    """generated == committed: editing STAGES without `scripts/gen_stages.py` (or hand-editing a copy) is red."""
    assert _gen().stale() == []


def test_the_schema_enum_is_the_stage_ids_in_attack_order_then_the_legacy_aliases():
    enum = SCHEMA["$defs"]["AttackStage"]["enum"]
    assert enum == [*stages.IDS, *stages.ALIASES]
    assert [s.order for s in stages.STAGES] == sorted(s.order for s in stages.STAGES)
    assert SCHEMA["$defs"]["ItemRef"]["properties"]["phase"]["$ref"] == "#/$defs/AttackStage"


def test_the_ui_table_lists_every_stage_with_its_label_and_controls():
    ts = (ROOT / "ui" / "src" / "generated" / "stages.ts").read_text()
    for s in stages.STAGES:
        assert f'"id": "{s.id}"' in ts and f'"zh": "{s.zh}"' in ts
        assert all(c.service in ts for c in s.controls)


def test_no_hand_copy_of_the_enum_is_left():
    """The contract of P1b: signals.PHASES and the UI's PHASE_ORDER / PHASE_LABEL / CORE are deleted, not kept beside."""
    from radar import signals
    assert not hasattr(signals, "PHASES") and not hasattr(signals, "phase")
    flow = (ROOT / "ui" / "src" / "utils" / "attackFlow.ts").read_text()
    for copy in ("PHASE_ORDER", "PHASE_LABEL", "const CORE", "'statement'", "'drain'"):
        assert copy not in flow, copy


# ── backward compatibility of published documents ───────────────────────────────────────────────────────────────────

M4_PHASES = ("prep", "drain", "laundering", "freeze", "statement", "attribution", "recovery", "impact", "other")


@pytest.mark.parametrize("old", M4_PHASES)
def test_every_m4_phase_value_reads_as_a_stage(old):
    """Event documents published before the rename carry M4 values; each maps to a stage, none falls to 'other'."""
    new = stages.canonical(old)
    assert new in stages.IDS and (new != "other" or old == "other")
    assert old in SCHEMA["$defs"]["AttackStage"]["enum"]           # still valid against the schema


def test_drain_and_statement_are_renamed_and_never_emitted():
    assert stages.canonical("drain") == "asset_transfer" and stages.canonical("statement") == "disclosure"
    assert not set(stages.ALIASES) & set(stages.IDS)
    assert set(stages.PRIORITY) <= set(stages.IDS) - {"other"}
    assert stages.canonical("no-such-stage") == "other" and stages.canonical(None) == "other"


# ── the cloud kill chain (04-reconstruction §0.3) ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(("title", "stage"), [
    # §0.3: both read as the drain before — the credential was swallowed by the theft
    ("Hackers used leaked AWS access keys to drain hot wallet", "credential_access"),
    ("Attacker gained access via phished AWS keys", "credential_access"),
    # the SlowMist / DeFiLlama title shapes of the 2026-10-29 Binance event (pipeline.py title comment)
    ("Binance DevOps Engineer's Laptop Compromised", "initial_access"),
    ("Binance Hot Wallet Key Compromised", "key_access"),
    ("黑客通过钓鱼邮件入侵员工电脑", "initial_access"),
    ("Attackers moved laterally into the production cluster", "lateral_movement"),
    ("Hackers escalated privileges to admin on the CI server", "privilege_escalation"),
    ("Attacker gained root access on the signing host", "privilege_escalation"),
    ("黑客入侵后成功提权", "privilege_escalation"),
    ("Backdoor planted in the exchange build server", "persistence"),
    ("Attackers executed malicious script on the CI runner", "execution"),
    ("Mass scanning for exposed Jenkins servers ahead of the theft", "recon"),
    # a phished employee is the way in; a retail wallet user losing funds to phishing is the theft (red team of P1b)
    ("Phishing campaign targeting exchange employees led to the breach", "initial_access"),
    ("⚠️ A victim lost $1.2M in WBTC to a phishing signature", "asset_transfer"),
    # priority: the victim's statement is a statement even when it names the keys
    ("Exchange investigating after AWS keys leaked", "disclosure"),
    # an advisory saying RCE / scanning is not an incident stage
    ("CVE-2026-1234: RCE in FooCMS", "other"),
])
def test_a_report_naming_how_the_attacker_got_in_is_that_stage(title, stage):
    assert stages.of_title(title) == stage


@pytest.mark.parametrize("title", [
    # the vulnerability class in an advisory title is not the incident's stage (review of p1/stages)
    "Canimaan Software ClamXAV local privilege escalation",
    "CVE-2026-21001: Windows Kernel privilege escalation vulnerability",
    "Linux kernel 本地提权漏洞",
    "Attackers could escalate privileges and move laterally via CVE-2026-1111",
    # "pivots to" in its business sense
    "Crypto exchange pivots to derivatives after hack",
])
def test_an_advisory_naming_a_vulnerability_class_is_no_cloud_stage(title):
    assert stages.BY_ID[stages.of_title(title)].segment != "cloud", stages.of_title(title)


def test_no_real_csaf_advisory_title_is_an_incident_stage():
    """Every title of the 2026-11-06 CISA CSAF feeds is a vulnerability advisory: none may read as a cloud stage — one did
    (ClamXAV local privilege escalation), and beside an "exploited in attacks" report a plain CVE event drew a two-stage
    权限提升 → 资产转出 flow with AWS controls."""
    from radar import parsers
    snap = ROOT / "tests" / "fixtures" / "snapshots" / "2026-11-06"
    titles = [i.title for f, src in (("cisa-csaf-it-feed.json", "cisa_csaf_it"), ("cisa-csaf-ot-feed.json", "cisa_csaf_ot"))
              for i in parsers.rolie((snap / f).read_text(), src)]
    assert any(t.endswith("Canimaan Software ClamXAV local privilege escalation") for t in titles)
    assert [t for t in titles if stages.BY_ID[stages.of_title(t)].segment == "cloud"] == []


def test_every_stage_has_a_label_and_valid_controls():
    domains = set(SCHEMA["$defs"]["Domain"]["enum"])
    for s in stages.STAGES:
        assert s.zh and s.en and s.segment in ("cloud", "chain", "response", "context")
        assert set(s.expected) <= domains
        assert all(c.effect in stages.EFFECT_ZH and c.service and c.how for c in s.controls)
        # a cloud stage exists to say which AWS control would have stopped or seen it
        assert s.segment != "cloud" or s.controls, s.id
        assert (s.cue is None) == (s.id not in stages.PRIORITY), s.id


def test_cloud_stages_are_never_listed_as_missing_evidence():
    """A flash-loan exploit has no lateral movement; listing seven cloud stages as 「尚无证据」 would be noise."""
    assert not any(s.expected for s in stages.STAGES if s.segment == "cloud")
    assert {s.id for s in stages.STAGES if "web3" in s.expected} == {
        "asset_transfer", "laundering", "freeze", "disclosure", "attribution", "recovery"}   # the old CORE, renamed


# ── on-chain rows are stage evidence (B8) ─────────────────────────────────────────────────────────────────────────────

V, R, X = "0xvictim", "0xrecv", "0xnext"


def _doc(rows, delegation=()):
    return {"rows": rows, "delegation": list(delegation)}


def test_each_chain_row_evidences_its_stage():
    doc = _doc([{"kind": "outflow", "t": "2026-10-29T20:30:00Z", "tx": "0xb", "from": V, "to": R},
                {"kind": "outflow", "t": "2026-10-29T20:24:23Z", "tx": "0xa", "from": V, "to": R},
                {"kind": "outflow", "t": "2026-10-29T20:33:23Z", "tx": "0xc", "from": R, "to": X},
                {"kind": "freeze", "t": "2026-10-29T21:01:35Z", "tx": "0xf", "issuer": "Tether"}],
               [{"address": V, "chain": "ethereum", "checked_at": "2026-10-30T00:00:00Z", "delegate": "0xdeleg"},
                {"address": "0xother", "chain": "ethereum", "checked_at": "2026-10-30T00:00:00Z", "delegate": None}])
    atx = {"txs": [{"tx": "0xatk", "t": "2026-10-29T20:20:00Z", "status": "success"},
                   {"tx": "0xrev", "t": "2026-10-29T20:00:00Z", "status": "reverted"}]}
    got = {(e["stage"], e["kind"]): (e["count"], e["first_at"], e["first_tx"]) for e in stages.chain_evidence(doc, {V}, atx)}
    assert got == {
        ("key_access", "delegation"): (1, "2026-10-30T00:00:00Z", None),
        ("asset_transfer", "attack_tx"): (1, "2026-10-29T20:20:00Z", "0xatk"),    # a reverted tx moved nothing
        ("asset_transfer", "outflow"): (2, "2026-10-29T20:24:23Z", "0xa"),        # earliest row, not the first listed
        ("laundering", "outflow"): (1, "2026-10-29T20:33:23Z", "0xc"),            # not from a victim: moved on
        ("freeze", "freeze"): (1, "2026-10-29T21:01:35Z", "0xf"),
    }
    assert [e["stage"] for e in stages.chain_evidence(doc, {V}, atx)] == [
        "key_access", "asset_transfer", "asset_transfer", "laundering", "freeze"]


def test_a_delegation_time_is_a_check_time_never_the_chain_clock():
    """An EIP-7702 delegation is read at check time (history not queried): its time is after the theft and must say so —
    as the chain clock it put 「密钥接触 链上 10-30 00:00」 before a 10-29 20:24 transfer (review of p1/stages)."""
    doc = _doc([{"kind": "outflow", "t": "2026-10-29T20:24:23Z", "tx": "0xa", "from": V, "to": R}],
               [{"address": V, "chain": "ethereum", "checked_at": "2026-10-30T00:00:00Z", "delegate": "0xdeleg"}])
    clocks = {e["kind"]: e["clock"] for e in stages.chain_evidence(doc, {V}, None)}
    assert clocks == {"delegation": "checked", "outflow": "chain"}


def test_the_clock_enum_and_the_kind_enum_are_stages_clock():
    cs = SCHEMA["$defs"]["ChainStage"]
    assert set(cs["properties"]["kind"]["enum"]) == set(stages.CLOCK)
    assert set(cs["properties"]["clock"]["enum"]) == set(stages.CLOCK.values())
    assert "clock" in cs["required"]


def test_no_chain_section_is_no_evidence():
    assert stages.chain_evidence(None, set(), None) == []


def test_the_binance_replay_confirms_transfer_laundering_and_freeze_to_the_second():
    """Real RPC replay of 2026-10-29 (tests/test_onchain.py): the 20:24:23 sweep out of Binance 14, the receiver's
    splits, the Tether / Circle freezes — three stages confirmed by the chain, half an hour before the first 快讯."""
    import test_onchain as T

    from radar import onchain
    case, _ = T.run(T.tape_call())
    doc = onchain.doc(case)
    ev = {e["stage"]: e for e in stages.chain_evidence(doc, onchain.victim_set(case), None)}
    assert ev["asset_transfer"]["first_at"] == "2026-10-29T20:24:23Z"
    assert ev["asset_transfer"]["first_tx"].startswith("0x53bd38b8")
    assert ev["laundering"]["count"] >= 2
    assert ev["freeze"]["count"] == sum(1 for r in doc["rows"] if r["kind"] == "freeze")


def test_the_event_document_publishes_the_chain_stage_evidence():
    from datetime import UTC, datetime

    import test_onchain as T
    from test_pipeline_replay import _raw

    from radar import onchain, pipeline, publish
    from radar.store import MemoryStore
    store = MemoryStore()
    t = datetime(2026, 10, 30, 3, tzinfo=UTC)
    pipeline.ingest([_raw("panews", "币安热钱包疑似遭攻击，约25亿美元资产被转出", "币安热钱包疑似遭攻击，约25亿美元资产被盗",
                          when="2026-10-29T20:51:50Z")], store, t)
    [ev] = [pipeline.Event.from_dict(d) for d in store.events.values()]
    assert ev.domain == "web3"
    case, _ = T.run(T.tape_call())
    store.put_source_state(onchain.case_key(ev.event_id), case)
    doc = publish.event_doc(ev, store, t)
    assert {s["stage"] for s in doc["chain_stages"]} >= {"asset_transfer", "laundering", "freeze"}
    assert [i["phase"] for i in doc["items"]] == ["asset_transfer"]
    jsonschema.validate(doc, SCHEMA)


def test_a_stale_copy_is_detected(monkeypatch):
    """The --check is alive: a stage table that changed without regenerating names the stale file."""
    gen = _gen()
    monkeypatch.setattr(stages, "ui_module", lambda: "// edited by hand\n")
    assert gen.stale() == [gen.UI]


def test_a_hack_database_record_naming_its_technique_is_still_the_transfer():
    """DeFiLlama's「Binance — Hot Wallet Key Compromised」is its category column, not a report of the key access: read as
    key_access, a database-only incident listed 资产转出 as having no evidence (red team of P1b)."""
    from datetime import UTC, datetime

    from test_pipeline_replay import _raw

    from radar import pipeline, publish
    from radar.store import MemoryStore
    store = MemoryStore()
    t = datetime(2026, 10, 30, 3, tzinfo=UTC)
    pipeline.ingest([_raw("defillama_hacks", "Binance — Hot Wallet Key Compromised", when="2026-10-29T00:00:00Z",
                          url="https://x/binance", extra={"entity": "Binance", "amount_usd": 6_300_000_000})], store, t)
    assert stages.of_title("Binance — Hot Wallet Key Compromised") == "key_access"     # a report would be key access
    [ev] = [pipeline.Event.from_dict(d) for d in store.events.values()]
    assert [i["phase"] for i in publish.event_doc(ev, store, t)["items"]] == ["asset_transfer"]
