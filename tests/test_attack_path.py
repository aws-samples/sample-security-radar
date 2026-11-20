"""R9.5 (requirement 2026-11-18): how a vulnerability is attacked — entry → condition → trigger → impact — and at which step
each defence stops it (WAF at the entry, a JVM flag on the host for now, the JDK upgrade for good). The model writes
grounded sentences; code checks them, places nothing it cannot place, and adds the radar's own defences."""
import json

from radar import analyst, attack_path
from radar.llm import LlmResult

EVIDENCE = [
    {"item_id": "a", "source": "watchTowr", "tier": "T2", "published_at": "2026-11-17T10:22:00Z",
     "title": "Java4Shell: pre-auth RCE in OpenJDK (CVE-2026-114938)",
     "text": "An attacker sends a crafted Base64 string in an HTTP request header to any Java service that decodes it. "
             "On x86-64 CPUs with AVX-512 VBMI the intrinsic decoder writes 62 bytes past the buffer, which gives code "
             "execution. Affected: OpenJDK 17.0.6 and later. Workaround: start the JVM with -XX:-UseBase64Intrinsics. "
             "Fix: update to the October 2026 release."},
]
GOOD = {
    "entry": [{"text": "攻击者在 HTTP 请求头中放入特制的 Base64 字符串，发送给会解码它的 Java 服务。", "cite": ["a"]}],
    "condition": [{"text": "服务运行在支持 AVX-512 VBMI 的 x86-64 CPU 上，OpenJDK 17.0.6 及以后版本。", "cite": ["a"]}],
    "trigger": [{"text": "内置解码器越界写入 62 字节。", "cite": ["a"]}],
    "impact": [{"text": "攻击者获得代码执行。", "cite": ["a"]}],
    "defenses": [
        {"text": "启动参数加 -XX:-UseBase64Intrinsics 关闭内置解码器。", "cite": ["a"], "stage": "trigger", "horizon": "temporary"},
        {"text": "升级到 2026 年 10 月版本。", "cite": ["a"], "stage": "trigger", "horizon": "fix"},
        {"text": "在网关丢弃异常长的 Base64 请求头。", "cite": ["a"], "stage": "sideways", "horizon": "block"},
    ],
}


def _call(payload):
    return lambda prompt, model, max_tokens: LlmResult("ok", json.dumps(payload, ensure_ascii=False), model=model)


def test_a_grounded_path_with_defences_placed_by_step_and_horizon():
    row = attack_path.build(EVIDENCE, "2026-11-19T00:00:00Z", call=_call(GOOD))
    assert [len(row["steps"][k]) for k in attack_path.STEPS] == [1, 1, 1, 1]
    assert [(d["stage"], d["horizon"]) for d in row["defenses"]] == [("trigger", "temporary"), ("trigger", "fix")]
    assert row["dropped_defenses"] == 1                       # an unknown stage is dropped and counted, never guessed
    assert row["status"] == "partial" and row["input_hash"] == attack_path.input_hash(analyst.trim_evidence(EVIDENCE))


def test_an_ungrounded_number_is_marked_like_the_brief_does():
    bad = {**GOOD, "trigger": [{"text": "内置解码器越界写入 640 字节。", "cite": ["a"]}], "defenses": []}
    row = attack_path.build(EVIDENCE, "2026-11-19T00:00:00Z", call=_call(bad))
    assert row["steps"]["trigger"][0]["issues"] == ["ungrounded_number"] and row["status"] == "partial"


def test_a_failed_call_or_nothing_explained_shows_nothing():
    fail = lambda prompt, model, max_tokens: LlmResult("error", "", model=model)
    assert attack_path.build(EVIDENCE, "t", call=fail)["status"] == "failed"
    empty = attack_path.build(EVIDENCE, "t", call=_call({"entry": [], "condition": [], "trigger": [], "impact": [], "defenses": []}))
    assert empty["status"] == "empty"
    assert attack_path.public({"status": "failed"}, rule_pack=True, aws_fix_line=None) is None
    assert attack_path.public(empty, rule_pack=True, aws_fix_line=None) is None


def test_the_page_adds_the_radars_own_defences_at_their_step():
    row = attack_path.build(EVIDENCE, "t", call=_call({**GOOD, "defenses": GOOD["defenses"][:1]}))
    pub = attack_path.public(row, rule_pack=True, aws_fix_line="🟧 AWS 已修复：Corretto 17/21 ｜ 不受影响：Corretto 8")
    own = [d for d in pub["defenses"] if d.get("source")]
    assert [(d["source"], d["stage"], d["horizon"]) for d in own] == [("radar", "entry", "block"), ("aws", "trigger", "fix")]
    assert own[1]["text"] == "AWS 已修复：Corretto 17/21"
    assert "input_hash" not in pub and "issues" not in json.dumps(pub)        # the cache key and issue codes stay inside
    no_fix = attack_path.public(row, rule_pack=False, aws_fix_line="🟧 AWS 待修复：Corretto 17")
    assert not [d for d in no_fix["defenses"] if d.get("source")]


def test_the_prompt_asks_for_the_four_steps_and_the_three_horizons_and_no_grading():
    p = attack_path.render_prompt(EVIDENCE)
    for w in ("entry:", "condition:", "trigger:", "impact:", "block", "temporary", "fix", "Do NOT guess", "Do NOT grade"):
        assert w in p
