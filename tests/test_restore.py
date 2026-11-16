"""R5.5: the restore plan makes a versioned bucket read as it did at a moment — and never deletes a version."""
from datetime import UTC, datetime, timedelta

from radar import restore

T0 = datetime(2026, 11, 15, 0, 0, tzinfo=UTC)


def v(key, vid, minutes):
    return {"Key": key, "VersionId": vid, "LastModified": T0 + timedelta(minutes=minutes)}


def test_the_plan_brings_back_what_was_current_at_the_moment():
    versions = [v("data/events.json", "a", 0), v("data/events.json", "b", 10), v("data/events.json", "c", 20),  # bad
                v("data/p0.json", "p", 0),                                                                       # untouched
                v("data/new.json", "n", 20),                                                                     # created after
                v("data/gone.json", "g", 0)]
    markers = [v("data/gone.json", "dm", 20),                                                                    # deleted after
               v("data/old.json", "dm2", 1)]                                                                     # deleted before, never back
    steps = {s.key: s for s in restore.plan(versions, markers + [], at=T0 + timedelta(minutes=15))}
    assert steps["data/events.json"] == restore.Step("data/events.json", "restore", "b")
    assert steps["data/p0.json"].action == "keep"
    assert steps["data/new.json"].action == "delete"
    assert steps["data/gone.json"] == restore.Step("data/gone.json", "restore", "g")
    assert "data/old.json" not in steps


def test_a_moment_before_the_key_existed_and_a_moment_exactly_on_a_write():
    versions = [v("k", "a", 5), v("k", "b", 10)]
    assert restore.plan(versions, [], at=T0) == [restore.Step("k", "delete")]
    assert restore.plan(versions, [], at=T0 + timedelta(minutes=10)) == [restore.Step("k", "keep", "b")]
    assert restore.plan(versions, [], at=T0 + timedelta(minutes=9)) == [restore.Step("k", "restore", "a")]
