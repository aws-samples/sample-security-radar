"""#/ops shows the shadow judge's measured quality and only the few pairs a fact cannot decide (Neo 11-19, step 3)."""
from radar import ops

EVS = [{"event_id": e, "title": t} for e, t in (("a", "Quest Diagnostics breach"), ("b", "Quest Diagnostics confirms"),
                                                 ("c", "Acme hacked"), ("d", "Acme drained"))]


def rep(**kw):
    return {"day": "2026-11-19", "at": "2026-11-19T00:00:00Z", "decided": 40, "same_said": 31, "same_precision": 1.0,
            "would_merge": 3, "would_merge_wrong": 0, "missed_same": 2, "rows": [], **kw}


def test_the_quality_line_says_whether_the_auto_merge_bar_is_met_and_warns_on_a_wrong_merge():
    (line,) = ops._judge_quality({"judge_truth": rep(), "events": EVS})
    assert line["level"] == "info" and "已达到" in line["detail"] and "判同 31 对" in line["title"]
    (bad,) = ops._judge_quality({"judge_truth": rep(would_merge_wrong=1), "events": EVS})
    assert bad["level"] == "warn" and "未达到" in bad["detail"]
    (low,) = ops._judge_quality({"judge_truth": rep(same_said=10, same_precision=0.9), "events": EVS})
    assert low["level"] == "warn"


def test_only_old_undecided_unlabelled_same_verdicts_are_shown_for_a_person():
    led = {"k1": {"a": "a", "b": "b", "verdict": "same", "by": "model", "at": "2026-11-01T00:00:00Z"},   # 18 days, shown
           "k2": {"a": "c", "b": "d", "verdict": "same", "by": "model", "at": "2026-11-15T00:00:00Z"},   # too new
           "k3": {"a": "c", "b": "d", "verdict": "different", "by": "model", "at": "2026-11-01T00:00:00Z"}}
    got = ops._judge_quality({"judge_truth": rep(), "cluster_judge": led, "events": EVS})
    look = [i for i in got if "请看一眼" in i["title"]]
    assert len(look) == 1 and "dup_label.py a b" in look[0]["detail"]
    labelled = ops._judge_quality({"judge_truth": rep(), "cluster_judge": led, "events": EVS, "dup_labels": {"a|b": {"label": "same"}}})
    assert not [i for i in labelled if "请看一眼" in i["title"]]
    decided = ops._judge_quality({"judge_truth": rep(rows=[{"a": "a", "b": "b"}]), "cluster_judge": led, "events": EVS})
    assert not [i for i in decided if "请看一眼" in i["title"]]
