"""M3.5 Security Hub criteria (B6): ASFF carries verdict + patch + mitigation state; unchanged findings are not
re-imported; a pair that is no longer affected is archived exactly once."""

from radar import securityhub as SH

EV = {"event_id": "ev_bb65db3b8694e5f4", "title": "PHP2Shell: CVE-2026-109618 / 109619", "severity": "P0",
      "cves": ["CVE-2026-109618", "CVE-2026-109619"], "first_seen": "2026-10-21T18:00:00Z"}
TGT = {"target_id": "demo-shop", "verdict": "affected", "detail": "3 处精确命中（受影响版本）",
       "locations": [{"file": "demo-shop/Dockerfile", "line": 1, "found_version": "8.3.30", "fixed_version": "8.3.36", "match": "exact"}]}
MIT = {"plans": [{"target_id": "demo-shop", "group_label": "PHP application", "tier": "cve", "state": "staged"}],
       "dns": None}
REQUIRED = ("SchemaVersion", "Id", "ProductArn", "GeneratorId", "AwsAccountId", "Types", "CreatedAt", "UpdatedAt",
            "Severity", "Title", "Description", "Resources")


def _f(now="2026-10-29T02:00:00Z", mit=MIT):
    return SH.asff(EV, TGT, mit, "123456789012", "ap-northeast-1", now, "https://radar.example")


def test_asff_has_every_required_field_and_the_whole_chain():
    f = _f()
    assert all(k in f for k in REQUIRED)
    assert f["Severity"]["Label"] == "CRITICAL" and f["Vulnerabilities"] == [{"Id": "CVE-2026-109618"}, {"Id": "CVE-2026-109619"}]
    assert "8.3.36" in f["Remediation"]["Recommendation"]["Text"] and "not a fix" in f["Remediation"]["Recommendation"]["Text"]
    assert "WAF PHP application (cve): staged" in f["Description"]
    assert f["Resources"][0]["Id"] == "demo-shop:demo-shop/Dockerfile:1"
    assert f["ProductArn"] == "arn:aws:securityhub:ap-northeast-1:123456789012:product/123456789012/default"


def test_unchanged_findings_are_not_reimported_but_a_mitigation_change_is():
    fid = SH.finding_id(EV["event_id"], "demo-shop")
    out, led = SH.plan({fid: _f()}, {}, "123456789012", "ap-northeast-1", "t")
    assert len(out) == 1
    out2, led2 = SH.plan({fid: _f(now="2026-10-29T03:00:00Z")}, led, "123456789012", "ap-northeast-1", "t")
    assert out2 == [] and led2 == led                              # only the timestamp moved
    blocked = {**MIT, "plans": [{**MIT["plans"][0], "state": "blocking"}]}
    out3, _ = SH.plan({fid: _f(mit=blocked)}, led, "123456789012", "ap-northeast-1", "t")
    assert len(out3) == 1 and "blocking" in out3[0]["Description"]


def test_a_pair_no_longer_affected_is_archived_once():
    fid = SH.finding_id(EV["event_id"], "demo-shop")
    _, led = SH.plan({fid: _f()}, {}, "123456789012", "ap-northeast-1", "t")
    out, led2 = SH.plan({}, led, "123456789012", "ap-northeast-1", "t2")
    assert [(f["Id"], f["RecordState"]) for f in out] == [(fid, "ARCHIVED")] and all(k in out[0] for k in REQUIRED)
    out2, _ = SH.plan({}, led2, "123456789012", "ap-northeast-1", "t3")
    assert out2 == []
