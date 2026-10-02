"""Publishing the anchor on a schedule, and recording how it is going."""

import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from runtime import anchor_git
from runtime.anchor_git import (AnchorGitError, AnchorRefused, publish_and_record, read_status, redact,
                                watch)
from runtime.chat import run_turn
from runtime.kernel import Kernel, KernelError, find_binary

try:
    find_binary()
except KernelError:
    pytest.skip("infinityctl not built (run `cargo build`)", allow_module_level=True)

ROOT = Path(__file__).resolve().parents[1]


class FakeClient:
    def __call__(self, url, payload, headers):
        return {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}


@pytest.fixture(autouse=True)
def keys(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k")


@pytest.fixture
def remote(tmp_path):
    path = tmp_path / "SECRET-REMOTE-NAME.git"
    subprocess.run(["git", "init", "--bare", "--quiet", str(path)], check=True)
    return str(path)


@pytest.fixture
def system(tmp_path):
    log, anchor = tmp_path / "log" / "r.jsonl", tmp_path / "local" / "a.jsonl"
    kernel = Kernel(receipt_log=log, anchor=anchor)

    def turns(n=1):
        for _ in range(n):
            run_turn("hi", "groq", kernel, client=FakeClient())

    return {"log": log, "anchor": anchor, "status": tmp_path / "state" / "status.json", "turns": turns}


def anchor_lines(path):
    return [line for line in Path(path).read_text().splitlines() if line.strip()]


# --- the status file ---------------------------------------------------------------------------

def test_a_successful_publish_is_recorded_without_naming_the_repository(system, remote):
    system["turns"](2)
    publish_and_record(system["anchor"], remote, status_file=system["status"], now=lambda: 1000)
    status = read_status(system["status"])
    assert status["last_success_at"] == 1000 and status["published_records"] == 4
    assert status["consecutive_failures"] == 0 and status["last_error"] is None
    assert status["integrity_failure"] is False
    assert status["head_receipt_id"] == json.loads(anchor_lines(system["anchor"])[-1])["head_receipt_id"]
    assert "SECRET-REMOTE-NAME" not in system["status"].read_text()
    assert not list(system["status"].parent.glob("*.tmp")), "the temporary file must be gone"


def test_a_failure_keeps_the_last_success_and_counts_up_and_a_success_resets_it(system, tmp_path, remote):
    system["turns"]()
    publish_and_record(system["anchor"], remote, status_file=system["status"], now=lambda: 1000)
    for expected in (1, 2):
        with pytest.raises(AnchorGitError):
            publish_and_record(system["anchor"], str(tmp_path / "no-such-repo.git"),
                               status_file=system["status"], now=lambda: 2000)
        status = read_status(system["status"])
        assert status["consecutive_failures"] == expected and status["last_attempt_at"] == 2000
        assert status["last_success_at"] == 1000 and status["published_records"] == 2  # not forgotten
        assert status["last_error"] and status["integrity_failure"] is False
    system["turns"]()
    publish_and_record(system["anchor"], remote, status_file=system["status"], now=lambda: 3000)
    status = read_status(system["status"])
    assert (status["consecutive_failures"], status["last_error"], status["published_records"]) == (0, None, 4)


def test_credentials_in_an_error_never_reach_the_status_file_or_the_printed_line(system, monkeypatch):
    system["turns"]()
    secret = "tok3n-must-not-leak"

    def leaky(*args, **kwargs):
        # what a git or network error can look like when the remote URL carries a token
        raise AnchorGitError(f"git push failed: unable to access 'https://deploy:{secret}@git.example/anchors.git/'")

    monkeypatch.setattr(anchor_git, "_publish", leaky)
    with pytest.raises(AnchorGitError):
        publish_and_record(system["anchor"], "https://x", status_file=system["status"])
    status_text = system["status"].read_text()
    assert secret not in status_text and "https://***@git.example/anchors.git" in status_text
    lines = []
    watch(system["anchor"], "https://x", status_file=system["status"], interval=1, max_runs=1,
          wait=lambda s: False, report=lines.append)
    assert lines and secret not in "\n".join(lines) and "***@" in lines[0]
    assert secret not in system["status"].read_text()


def test_a_multi_line_git_error_becomes_one_line_in_the_log_and_the_status(system, monkeypatch):
    system["turns"]()

    def noisy(*args, **kwargs):
        raise AnchorGitError("git ls-remote failed: fatal: 'x' does not appear to be a git repository\n"
                             "fatal: Could not read from remote repository.\n\n   Please check access rights.")

    monkeypatch.setattr(anchor_git, "_publish", noisy)
    lines = []
    watch(system["anchor"], "x", status_file=system["status"], interval=1, max_runs=1, wait=lambda s: False,
          report=lines.append)
    assert len(lines) == 1 and "\n" not in lines[0]
    assert "\n" not in read_status(system["status"])["last_error"]
    assert "Could not read from remote repository. Please check access rights." in lines[0]


def test_redact_hides_url_credentials_and_leaves_other_text_alone():
    secret = "tok3n-must-not-leak"
    assert redact(f"fatal: https://user:{secret}@host/x.git failed") == "fatal: https://***@host/x.git failed"
    assert redact(f"ssh://git:{secret}@host/x") == "ssh://***@host/x"
    assert redact("git@github.com:org/repo.git") == "git@github.com:org/repo.git"  # no scheme, nothing to hide
    assert redact("https://host/path?a=b@c") == "https://host/path?a=b@c"  # an @ after the first slash is not a login


def test_a_real_unreachable_remote_with_a_token_in_its_url_leaves_no_token_behind(system):
    system["turns"]()
    secret = "tok3n-must-not-leak"
    with pytest.raises(AnchorGitError):
        publish_and_record(system["anchor"], f"https://user:{secret}@127.0.0.1:1/x.git", status_file=system["status"])
    assert secret not in system["status"].read_text()


def test_a_log_that_does_not_match_its_anchor_is_an_integrity_refusal_not_a_network_error(system, remote):
    system["turns"](2)
    system["log"].write_text("\n".join(anchor_lines(system["log"])[:-1]) + "\n")  # newest entry deleted
    with pytest.raises(AnchorRefused):
        publish_and_record(system["anchor"], remote, log=system["log"], status_file=system["status"])
    status = read_status(system["status"])
    assert status["integrity_failure"] is True and "does not match" in status["last_error"]
    assert status["last_success_at"] is None
    # an ordinary network failure is a different thing
    with pytest.raises(AnchorGitError) as err:
        publish_and_record(system["anchor"], "/no/such/repo", status_file=system["status"])
    assert not isinstance(err.value, AnchorRefused)
    assert read_status(system["status"])["integrity_failure"] is False


def test_a_shortened_anchor_is_an_integrity_refusal(system, remote):
    system["turns"](2)
    publish_and_record(system["anchor"], remote, status_file=system["status"])
    system["anchor"].write_text("\n".join(anchor_lines(system["anchor"])[:-2]) + "\n")
    with pytest.raises(AnchorRefused, match="does not continue"):
        publish_and_record(system["anchor"], remote, status_file=system["status"])
    assert read_status(system["status"])["integrity_failure"] is True


def test_a_crash_while_writing_the_status_leaves_the_previous_status_intact(system, remote, monkeypatch):
    system["turns"]()
    publish_and_record(system["anchor"], remote, status_file=system["status"], now=lambda: 1000)
    before = system["status"].read_text()
    system["turns"]()

    def crash(*args, **kwargs):
        raise OSError("disk went away")

    monkeypatch.setattr(os, "replace", crash)
    with pytest.raises(OSError):
        publish_and_record(system["anchor"], remote, status_file=system["status"], now=lambda: 2000)
    monkeypatch.undo()
    assert system["status"].read_text() == before, "a reader must never see a half-written status"
    assert json.loads(before)["last_success_at"] == 1000


def test_a_missing_or_garbled_status_file_reads_as_nothing(tmp_path):
    assert read_status(tmp_path / "none.json") is None
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert read_status(bad) is None
    bad.write_text("[1, 2]")
    assert read_status(bad) is None


# --- the loop ----------------------------------------------------------------------------------

def test_the_loop_publishes_new_records_each_time_it_runs(system, remote):
    system["turns"]()
    delays = []

    def wait(seconds):
        delays.append(seconds)
        system["turns"]()  # more activity between runs
        return False

    lines = []
    watch(system["anchor"], remote, status_file=system["status"], interval=60, max_runs=3, wait=wait,
          report=lines.append)
    assert delays == [60, 60]
    assert read_status(system["status"])["published_records"] == 6
    assert len(anchor_git.published_anchor(remote)) == 6
    commits = subprocess.run(["git", "--git-dir", remote, "log", "--format=%s", "anchors"],
                             capture_output=True, text=True, check=True).stdout.splitlines()
    assert len(commits) == 3 and len(lines) == 3 and all("published" in line for line in lines)


def test_failures_back_off_up_to_a_limit_and_recover_to_the_normal_interval(system, tmp_path):
    system["turns"]()
    repo = tmp_path / "later.git"
    delays = []

    def wait(seconds):
        delays.append(seconds)
        if len(delays) == 5:  # the remote comes back
            subprocess.run(["git", "init", "--bare", "--quiet", str(repo)], check=True)
        return False

    lines = []
    watch(system["anchor"], str(repo), status_file=system["status"], interval=10, max_backoff=50,
          max_runs=7, wait=wait, report=lines.append)
    assert delays == [10, 20, 40, 50, 50, 10]  # doubles, is capped, then back to normal after a success
    assert sum("publish failed" in line for line in lines) == 5
    assert read_status(system["status"])["consecutive_failures"] == 0


def test_an_integrity_refusal_does_not_stop_the_loop_or_speed_it_up_or_slow_it_down(system, remote):
    system["turns"](2)
    publish_and_record(system["anchor"], remote, status_file=system["status"])
    system["anchor"].write_text("\n".join(anchor_lines(system["anchor"])[:-1]) + "\n")
    delays, lines = [], []
    watch(system["anchor"], remote, status_file=system["status"], interval=30, max_runs=3,
          wait=lambda s: delays.append(s) or False, report=lines.append)
    assert delays == [30, 30] and all("INTEGRITY REFUSAL" in line for line in lines)
    assert read_status(system["status"])["integrity_failure"] is True


def test_the_loop_stops_when_asked(system, remote):
    system["turns"]()
    stop = threading.Event()
    runner = threading.Thread(target=watch, args=(system["anchor"], remote),
                              kwargs=dict(status_file=system["status"], interval=3600, stop=stop,
                                          report=lambda line: None))
    runner.start()
    deadline = time.time() + 20
    while read_status(system["status"]) is None and time.time() < deadline:
        time.sleep(0.05)
    stop.set()
    runner.join(timeout=10)
    assert not runner.is_alive() and read_status(system["status"])["last_success_at"]


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_the_command_stops_cleanly_on_a_signal(system, remote, sig):
    system["turns"]()
    proc = subprocess.Popen(
        [sys.executable, "-m", "runtime.anchor_git", "watch", "--anchor", str(system["anchor"]), "--repo", remote,
         "--status-file", str(system["status"]), "--interval", "3600"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.time() + 30
    while read_status(system["status"]) is None and time.time() < deadline:
        time.sleep(0.05)
    assert read_status(system["status"]), "the first publish should have happened"
    proc.send_signal(sig)
    out, err = proc.communicate(timeout=15)
    assert proc.returncode == 0 and "Traceback" not in err, err
    assert "watching" in out


def test_command_line_checks(system, remote, capsys):
    base = ["watch", "--anchor", str(system["anchor"]), "--repo", remote]
    with pytest.raises(SystemExit):
        anchor_git.main(base)  # --status-file is required
    with pytest.raises(SystemExit):
        anchor_git.main(base + ["--status-file", str(system["status"]), "--interval", "0"])
    with pytest.raises(SystemExit):
        anchor_git.main(base + ["--status-file", str(system["status"]), "--interval", "100", "--max-backoff", "10"])
    # an hourly schedule is legitimate and must start (its backoff cap defaults to at least the interval)
    assert anchor_git.main(base + ["--status-file", str(system["status"]), "--interval", "3600", "--max-runs", "1"]) == 0


def test_one_shot_publish_can_record_its_status_too(system, remote):
    system["turns"]()
    assert anchor_git.main(["publish", "--anchor", str(system["anchor"]), "--repo", remote,
                            "--status-file", str(system["status"])]) == 0
    assert read_status(system["status"])["published_records"] == 2
    assert anchor_git.main(["publish", "--anchor", str(system["anchor"]), "--repo", "/no/such/repo",
                            "--status-file", str(system["status"])]) == 1
    status = read_status(system["status"])
    assert status["consecutive_failures"] == 1 and status["last_success_at"]
