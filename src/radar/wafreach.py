"""Can AWS WAF stop this vulnerability? (Neo 2026-11-24: 「如果不能 WAF 阻拦，要写清楚为什么不能」 — MySQL CVE-2026-114952's
page said 「雷达生成的 WAF 规则包：在入口匹配攻击请求」 while its pack was empty and MySQL traffic never passes a WAF.)

AWS WAF inspects HTTP(S) requests at CloudFront / ALB / API Gateway / AppSync and nothing else. Decided by code, from the
affected product (radar.p0class) and the event's rule pack (radar.rulepack):
  - the pack holds a rule                → WAF can help (the page keeps its 「立即拦截」 defence);
  - the product speaks its own protocol  → it cannot: 「攻击走 MySQL 协议（端口 3306），不经过 HTTP …」, and the defence
                                            that does work is network access (only the app servers reach that port);
  - an OS / local component              → it cannot: the attack is not a web request;
  - an HTTP service without a rule       → it cannot here: the pack's own `no_rule` reason (no request feature, no CWE).
No pack computed (the event was never evaluated) ⇒ nothing is claimed either way."""
from __future__ import annotations

from typing import Any

from radar import p0class, rulepack

# product tile → (protocol, port) — services reached over their own TCP protocol, never through an HTTP front door
NON_HTTP: dict[str, tuple[str, str]] = {
    "mysql": ("MySQL 协议", "3306"), "postgres": ("PostgreSQL 协议", "5432"), "redis": ("Redis 协议", "6379"),
    "mongodb": ("MongoDB 协议", "27017"), "kafka": ("Kafka 协议", "9092"), "mq": ("AMQP / OpenWire 协议", "5672 / 61616"),
    "mqtt": ("MQTT 协议", "1883 / 8883"), "openssh": ("SSH 协议", "22"),
    "dbother": ("数据库 / 协调服务的自有协议", "服务端口"),
}
LOCAL_GROUPS = frozenset({"os"})          # kernel, glibc, sudo, systemd …: local or host-level, not a web request


def assess(title: str, entities: list[str] | None, pack: dict[str, Any] | None) -> dict[str, Any] | None:
    """None when there is nothing to say (no pack, or the pack has a rule). Else {why, network}: why WAF cannot stop it,
    and — for a non-HTTP service — the network step that does."""
    if not pack or rulepack.has_rules(pack):
        return None
    pl = p0class.place(title, entities)
    if pl.product in NON_HTTP:
        proto, port = NON_HTTP[pl.product]
        return {"why": f"AWS WAF 拦不住：攻击走 {proto}（端口 {port}），不经过 HTTP，WAF 只检查 Web 请求，看不到这类流量",
                "network": f"收紧网络访问：{port} 端口只对应用服务器开放（安全组 / 网络 ACL），不对公网开放"}
    if pl.group in LOCAL_GROUPS:
        return {"why": "AWS WAF 拦不住：漏洞在操作系统 / 本机组件里，攻击不经过 Web 请求", "network": None}
    reason = (pack.get("no_rule") or "").strip()
    return {"why": f"AWS WAF 拦不住：{reason}" if reason else "AWS WAF 拦不住：写不出既拦得住、又不误拦正常流量的边缘规则",
            "network": None}
