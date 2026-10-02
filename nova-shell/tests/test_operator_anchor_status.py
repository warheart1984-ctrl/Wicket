"""The operator screen shows how fresh the published anchor is, from a status file another process writes."""

import http.client
import json
import threading
import time

import pytest

from nova.operator_ui import OperatorConfig, make_server


class Screen:
    def __init__(self, tmp_path, status=None, stale_after=900.0, anchor_lines=0):
        self.tmp = tmp_path
        self.status = tmp_path / "status.json" if status is not False else None
        self.anchor = tmp_path / "anchor.jsonl"
        self.anchor.write_text("".join(json.dumps({"n": i}) + "\n" for i in range(anchor_lines)))
        self.server, self.token = make_server(OperatorConfig(
            tmp_path / "human" / "ap.jsonl", tmp_path / "state", anchor=self.anchor,
            publish_status=self.status, publish_stale_after=stale_after))
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def write(self, **status):
        base = {"version": "infinity.anchor-publish-status.v1", "last_attempt_at": int(time.time()),
                "last_success_at": int(time.time()), "published_records": 0, "head_receipt_id": None,
                "consecutive_failures": 0, "last_error": None, "integrity_failure": False}
        self.status.write_text(json.dumps({**base, **status}))

    def state(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        conn.request("GET", "/api/state", headers={"Host": f"127.0.0.1:{self.port}",
                                                   "Authorization": f"Bearer {self.token}"})
        data = json.loads(conn.getresponse().read())
        conn.close()
        return data["anchor_publish"]


@pytest.fixture
def make(tmp_path):
    made = []

    def build(**kwargs):
        made.append(Screen(tmp_path, **kwargs))
        return made[-1]

    yield build
    for screen in made:
        screen.server.shutdown()


def test_without_a_status_file_it_says_publishing_is_not_monitored(make):
    assert make(status=False).state() == {"monitored": False}


def test_a_status_file_that_does_not_exist_yet_means_it_has_never_run(make):
    assert make().state() == {"monitored": True, "known": False}


def test_a_fresh_publish_is_not_stale(make):
    screen = make(anchor_lines=10)
    screen.write(last_success_at=int(time.time()) - 30, published_records=10)
    state = screen.state()
    assert state["known"] and state["stale"] is False and state["unpublished_records"] == 0
    assert 29 <= state["age_seconds"] < 60 and state["consecutive_failures"] == 0


def test_it_counts_the_entries_that_are_not_yet_protected_by_a_publish(make):
    screen = make(anchor_lines=17)
    screen.write(published_records=12)
    assert screen.state()["unpublished_records"] == 5


def test_an_old_success_is_stale_and_the_threshold_is_configurable(make):
    screen = make(stale_after=60)
    screen.write(last_success_at=int(time.time()) - 120)
    assert screen.state()["stale"] is True
    screen.server.shutdown()
    (screen.tmp / "lenient").mkdir()
    lenient = Screen(screen.tmp / "lenient", stale_after=600)
    try:
        lenient.write(last_success_at=int(time.time()) - 120)
        assert lenient.state()["stale"] is False  # the same age is fine under a longer threshold
    finally:
        lenient.server.shutdown()


def test_it_never_having_succeeded_counts_as_stale(make):
    screen = make()
    screen.write(last_success_at=None, published_records=None, consecutive_failures=3, last_error="no route to host")
    state = screen.state()
    assert state["stale"] is True and state["last_success_at"] is None and state["consecutive_failures"] == 3
    assert state["unpublished_records"] is None


def test_failures_and_integrity_refusals_are_passed_through(make):
    screen = make()
    screen.write(consecutive_failures=4, last_error="git push failed", integrity_failure=True)
    state = screen.state()
    assert state["consecutive_failures"] == 4 and state["integrity_failure"] is True
    assert state["last_error"] == "git push failed"


def test_a_clock_in_the_future_is_treated_as_just_now_not_as_negative_time(make):
    screen = make()
    screen.write(last_success_at=int(time.time()) + 100000)
    assert screen.state()["age_seconds"] == 0.0


@pytest.mark.parametrize("garbage", [
    "{not json", "[1, 2, 3]", "null", '"a string"', "12", "",
])
def test_a_garbled_status_file_reads_as_never_run_not_as_a_crash(make, garbage):
    screen = make()
    screen.status.write_text(garbage)
    assert screen.state() == {"monitored": True, "known": False}


def test_wrongly_typed_fields_fall_back_to_safe_values(make):
    screen = make(anchor_lines=5)
    screen.status.write_text(json.dumps({
        "last_success_at": "yesterday", "published_records": "lots", "consecutive_failures": "x",
        "last_error": ["not", "a", "string"], "integrity_failure": "yes"}))
    state = screen.state()
    assert state["last_success_at"] is None and state["unpublished_records"] is None
    assert state["consecutive_failures"] == 0 and state["last_error"] is None
    assert state["integrity_failure"] is False  # only a real `true` counts, not a truthy string
    screen.status.write_text(json.dumps({"consecutive_failures": -5, "published_records": True, "last_success_at": True}))
    state = screen.state()
    assert state["consecutive_failures"] == 0 and state["unpublished_records"] is None and state["last_success_at"] is None


def test_a_huge_error_message_is_cut_short(make):
    screen = make()
    screen.write(last_error="x" * 100000)
    assert len(screen.state()["last_error"]) == 300


def test_hostile_text_in_the_status_file_is_only_ever_data(make):
    screen = make()
    screen.write(last_error="<img src=x onerror=alert(1)>", consecutive_failures=1)
    assert screen.state()["last_error"] == "<img src=x onerror=alert(1)>"
