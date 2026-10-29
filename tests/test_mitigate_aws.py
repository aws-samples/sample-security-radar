"""Adapter guards that only show up live (M3): field limits the AWS APIs enforce. Stubbed clients, no network."""

from radar import mitigate, mitigate_aws


class _R53R:
    def __init__(self):
        self.calls = []

    def update_firewall_domains(self, **kw):
        self.calls.append(("domains", kw))

    def create_firewall_rule(self, **kw):
        self.calls.append(("create", kw))

    def update_firewall_rule(self, **kw):
        self.calls.append(("update", kw))


def test_creator_request_id_fits_the_64_char_limit_and_is_deterministic(monkeypatch):
    stub = _R53R()
    monkeypatch.setitem(mitigate_aws._clients, "r53r", stub)
    cfg = {"rule_group_id": "rslvr-frg-" + "a" * 16, "domain_list_id": "rslvr-fdl-" + "b" * 16}
    rules = mitigate.dns_rules(cfg["domain_list_id"], {n: f"rslvr-fdl-{i:016d}" for i, n in enumerate(mitigate.DNS_MANAGED_LISTS)}, set())
    assert mitigate_aws.dns_put(cfg, None, rules, []) == {}
    ids = [kw["CreatorRequestId"] for op, kw in stub.calls if op == "create"]
    assert len(ids) == len(rules) and all(1 <= len(i) <= 64 for i in ids) and len(set(ids)) == len(ids)
    stub.calls.clear()
    mitigate_aws.dns_put(cfg, None, rules, [])
    assert [kw["CreatorRequestId"] for _, kw in stub.calls] == ids     # a retry reuses the same ids


def test_put_rules_refuses_a_web_acl_outside_the_radar_prefix():
    out = mitigate_aws.put_rules({"name": "n8n-waf"}, {"Name": "n8n-waf"}, "L", [])
    assert "refusing" in out["error"]
