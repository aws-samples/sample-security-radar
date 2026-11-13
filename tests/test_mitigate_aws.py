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


def test_group_meta_carries_the_group_rule_names_a_promotion_needs(monkeypatch):
    """W1: a promoted plan keeps every rule it does not name at Count — the names come from DescribeManagedRuleGroup."""
    class _Waf:
        def describe_managed_rule_group(self, **kw):
            return {"Rules": [{"Name": "PHP2Shell_BODY", "Action": {"Block": {}}},
                              {"Name": "PHPHighRiskMethodsVariables_BODY", "Action": {"Block": {}}}],
                    "AvailableLabels": [{"Name": "awswaf:managed:aws:php-app:PHP2Shell_Body"}]}

        def list_available_managed_rule_group_versions(self, **kw):
            return {"CurrentDefaultVersion": "Version_2.5"}
    monkeypatch.setitem(mitigate_aws._clients, "waf", _Waf())
    assert mitigate_aws.group_meta("AWSManagedRulesPHPRuleSet") == {
        "labels": ["awswaf:managed:aws:php-app:PHP2Shell_Body"],
        "rules": ["PHP2Shell_BODY", "PHPHighRiskMethodsVariables_BODY"], "default_version": "Version_2.5"}


def test_put_rules_refuses_a_web_acl_outside_the_radar_prefix():
    out = mitigate_aws.put_rules({"name": "n8n-waf"}, {"Name": "n8n-waf"}, "L", [])
    assert "refusing" in out["error"]
