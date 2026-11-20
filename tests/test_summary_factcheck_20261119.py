"""The grounded BLUF becomes the event summary → the Slack P0 line, feeds, webhooks, the site. It may not contradict
the code's own fields (harness audit 11-19: grounding checks citations and numbers only; 61 % of passing sentences
have no number). Replay of 785 live briefs: 8 first sentences rejected before the CVE rule was narrowed, 1 after."""
from radar import analyst

V = {"cves": ["CVE-2026-109593", "CVE-2026-109594"], "exploitation": "none", "amount_usd_latest": None, "amount_disputed": False}


def test_exploited_claim_against_the_code_is_rejected_and_a_negation_is_not_a_claim():
    live = "SonicWall 披露两项不会修补的 GMS 终止支持版本漏洞,并发布更新修复一个已被利用的 SSL-VPN 认证绕过漏洞。"
    assert analyst.contradiction(live, V) == "exploited_claim_not_in_code"
    assert analyst.contradiction("目前尚无在野利用的报道。", V) is None
    assert analyst.contradiction("There is no evidence of exploitation in the wild yet.", V) is None
    assert analyst.contradiction(live, {**V, "exploitation": "reported"}) is None


def test_denying_a_confirmed_exploitation_is_rejected():
    assert analyst.contradiction("尚无在野利用报道。", {**V, "exploitation": "confirmed"}) == "denies_confirmed_exploitation"


def test_a_cve_the_event_does_not_hold_is_rejected_only_when_the_event_has_cves():
    assert analyst.contradiction("CVE-2026-55555 被修补。", V) == "cve_not_in_event"
    assert analyst.contradiction("Google 已修补 Chrome 零日漏洞 CVE-2026-125350。", {**V, "cves": []}) is None
    assert analyst.contradiction("CVE-2026-109593 被修补。", V) is None


def test_an_amount_far_from_the_events_is_rejected():
    w = {**V, "cves": [], "amount_usd_latest": 12_000_000}
    assert analyst.contradiction("Attackers drained $40 million.", w) == "amount_not_event"
    assert analyst.contradiction("Attackers drained $12.5M.", w) is None
    assert analyst.contradiction("Attackers drained $40 million.", {**w, "amount_disputed": True}) is None


def test_the_published_summary_falls_back_to_the_code_summary_and_says_why():
    from radar import publish
    from radar.model import Event
    ev = Event(event_id="ev_0000000000000001", domain="vuln", title="t", first_seen="2026-11-19T00:00:00Z",
               last_updated="2026-11-19T00:00:00Z", item_ids=[], keys=[], severity="P1", summary="code summary",
               analysis={"bluf": [{"text": "一个已被利用的漏洞。", "cite": ["a"], "grounded": True}]})
    out = publish._summary_field(ev)
    assert out == {"summary": "code summary", "summary_source": "code", "summary_rejected": ["exploited_claim_not_in_code"]}
