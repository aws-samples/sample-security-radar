"""Audit 04 6.6 (R4.2): CreateCodeReview has no idempotency token. A StartCodeReviewJob that failed after the create
left a review object behind, and every retry created another. The retry now starts the review it already created."""

import pytest

from radar import continuum_aws as C
from radar import respond

TITLE = "radar-ev_abc-demo-shop"


class FakeSA:
    def __init__(self, reviews=(), jobs=None, fail_start=0, page=2):
        self.reviews = [dict(r) for r in reviews]
        self.jobs = dict(jobs or {})          # review id → job ids
        self.fail_start, self.page, self.created, self.started = fail_start, page, [], []

    def list_code_reviews(self, agentSpaceId, nextToken=None):
        i = int(nextToken or 0)
        out = {"codeReviewSummaries": self.reviews[i:i + self.page]}
        if i + self.page < len(self.reviews):
            out["nextToken"] = str(i + self.page)
        return out

    def list_code_review_jobs_for_code_review(self, agentSpaceId, codeReviewId, maxResults):
        return {"codeReviewJobSummaries": [{"codeReviewJobId": j} for j in self.jobs.get(codeReviewId, [])][:maxResults]}

    def create_code_review(self, title, **kw):
        cid = f"cr-{len(self.reviews) + 1}"
        self.reviews.append({"codeReviewId": cid, "title": title, "createdAt": f"2026-11-15T00:0{len(self.reviews)}:00Z"})
        self.created.append(cid)
        return {"codeReviewId": cid}

    def start_code_review_job(self, agentSpaceId, codeReviewId):
        if self.fail_start:
            self.fail_start -= 1
            raise RuntimeError("ThrottlingException")
        self.started.append(codeReviewId)
        self.jobs.setdefault(codeReviewId, []).append(f"job-{codeReviewId}")
        return {"codeReviewJobId": f"job-{codeReviewId}"}


@pytest.fixture
def env(monkeypatch):
    for k, v in {"SA_AGENT_SPACE_ID": "as-1", "SA_SERVICE_ROLE_ARN": "arn:aws:iam::1:role/r", "SA_CODE_BUCKET": "b"}.items():
        monkeypatch.setenv(k, v)


def _start(sa, monkeypatch):
    monkeypatch.setattr(C, "_sa", lambda: sa)
    return C._start_review(respond.Op("start_review", "demo-shop", {}), {"event_id": "ev_abc"})


def test_a_start_that_failed_after_the_create_is_retried_on_the_same_review(env, monkeypatch):
    sa = FakeSA(fail_start=1)
    with pytest.raises(RuntimeError):
        _start(sa, monkeypatch)
    out = _start(sa, monkeypatch)
    assert sa.created == ["cr-1"] and sa.started == ["cr-1"] and out["code_review_id"] == "cr-1"


def test_a_review_that_already_ran_is_history_and_a_new_one_is_created(env, monkeypatch):
    """An escalated event reviews the same target again under the same title: the finished review is not reused."""
    sa = FakeSA(reviews=[{"codeReviewId": "cr-old", "title": TITLE, "createdAt": "2026-11-01T00:00:00Z"}],
                jobs={"cr-old": ["job-old"]})
    out = _start(sa, monkeypatch)
    assert sa.created == ["cr-2"] and out["code_review_id"] == "cr-2"


def test_the_unstarted_review_is_found_past_the_first_page_and_only_by_its_own_title(env, monkeypatch):
    other = [{"codeReviewId": f"x{i}", "title": f"radar-ev_other-{i}", "createdAt": "2026-11-02"} for i in range(5)]
    sa = FakeSA(reviews=[*other, {"codeReviewId": "cr-mine", "title": TITLE, "createdAt": "2026-11-03"},
                         {"codeReviewId": "cr-near", "title": TITLE + "-x", "createdAt": "2026-11-04"}])
    out = _start(sa, monkeypatch)
    assert sa.created == [] and out["code_review_id"] == "cr-mine"
