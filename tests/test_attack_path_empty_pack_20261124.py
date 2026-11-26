"""MySQL CVE-2026-114952 (live 2026-11-24): the rule pack is empty (no request feature, no CWE — the attack is the MySQL
protocol, which never passes a WAF), yet the attack path said 「雷达生成的 WAF 规则包：在入口匹配攻击请求」. Neo: 「如果不能
WAF 阻拦，要写清楚为什么不能」. The WAF defence is placed only when the pack holds a rule; otherwise the page says why not."""
from __future__ import annotations

from radar import attack_path, rulepack, wafreach

EMPTY = {"managed": [], "custom": [], "templates": [],
         "no_rule": "公告没有给出攻击请求的特征（端点、参数、请求头），也没有弱点类型（CWE）：写不出既拦得住、又不误拦正常流量的边缘规则"}
RULED = {"managed": ["AWSManagedRulesSQLiRuleSet"], "custom": [], "templates": []}
ROW = {"status": "ok", "generated_at": "t", "defenses": [], "steps": {
    "entry": [{"text": "无需认证，经网络访问", "cite": ["it_1"], "grounded": True}], "condition": [], "trigger": [], "impact": []}}


def test_has_rules():
    assert not rulepack.has_rules(None) and not rulepack.has_rules(EMPTY)
    assert rulepack.has_rules(RULED) and rulepack.has_rules({"managed": [], "custom": [{"name": "x"}]})


def test_a_non_http_service_says_its_protocol_and_the_network_step():
    w = wafreach.assess("CVE-2026-114952 Vulnerability in the MySQL Server", ["Oracle", "MySQL"], EMPTY)
    assert "MySQL 协议（端口 3306）" in w["why"] and "不经过 HTTP" in w["why"]
    assert "3306 端口只对应用服务器开放" in w["network"]


def test_an_os_component_is_not_a_web_request():
    w = wafreach.assess("Linux kernel use-after-free in io_uring", [], EMPTY)
    assert "操作系统" in w["why"] and w["network"] is None


def test_an_http_product_without_a_rule_gives_the_packs_reason():
    w = wafreach.assess("CVE-2026-1 GitLab CE stored XSS", [], EMPTY)
    assert w["why"].startswith("AWS WAF 拦不住：公告没有给出攻击请求的特征")


def test_nothing_is_claimed_when_a_rule_exists_or_no_pack_was_built():
    assert wafreach.assess("MySQL Server flaw", [], RULED) is None
    assert wafreach.assess("MySQL Server flaw", [], None) is None


def test_the_page_never_claims_an_empty_pack_blocks():
    waf = wafreach.assess("CVE-2026-114952 Vulnerability in the MySQL Server", [], EMPTY)
    pub = attack_path.public(ROW, rule_pack=rulepack.has_rules(EMPTY), aws_fix_line=None, waf=waf)
    texts = [(d["horizon"], d["text"]) for d in pub["defenses"]]
    assert not any("雷达生成的 WAF 规则包" in t for _, t in texts)
    assert ("none", waf["why"]) in texts and ("temporary", waf["network"]) in texts
    ruled = attack_path.public(ROW, rule_pack=True, aws_fix_line=None, waf=None)
    assert any(h == "block" and "雷达生成的 WAF 规则包" in t for h, t in [(d["horizon"], d["text"]) for d in ruled["defenses"]])
