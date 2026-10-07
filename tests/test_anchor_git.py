import json
import subprocess
from pathlib import Path

import pytest

from runtime import anchor_git
from runtime.anchor_git import AnchorGitError, publish, published_anchor, verify
from runtime.chat import run_turn
from runtime.kernel import Kernel, KernelError, find_binary

try:
    find_binary()
except KernelError:
    pytest.skip("infinityctl not built (run `cargo build`)", allow_module_level=True)


class FakeClient:
    def __call__(self, url, payload, headers):
        return {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}


@pytest.fixture(autouse=True)
def keys(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    # These tests need a completed provider call. Explicit local-dev opt-out, not the default.
    monkeypatch.setenv("WICKET_ALLOW_DIRECT_CALLS", "1")


@pytest.fixture
def remote(tmp_path):
    path = tmp_path / "anchors.git"
    subprocess.run(["git", "init", "--bare", "--quiet", str(path)], check=True)
    return str(path)


@pytest.fixture
def system(tmp_path):
    """A kernel with a chained log and anchor on 'the log writer's machine'."""
    log, anchor = tmp_path / "log" / "r.jsonl", tmp_path / "local" / "a.jsonl"
    kernel = Kernel(receipt_log=log, anchor=anchor)

    def turns(n):
        for _ in range(n):
            run_turn("hi", "groq", kernel, client=FakeClient())

    return kernel, log, anchor, turns


ENTRIES_PER_TURN = 2  # each turn writes a decision and, after the model call, its outcome


def commits(remote, branch="anchors"):
    out = subprocess.run(["git", "--git-dir", remote, "log", "--format=%s", branch],
                         capture_output=True, text=True, check=True).stdout
    return out.splitlines()


def lines(path):
    return [line for line in Path(path).read_text().splitlines() if line.strip()]


def test_first_publish_creates_the_branch_with_the_anchor(system, remote):
    kernel, log, anchor, turns = system
    turns(3)
    assert f"published {3 * ENTRIES_PER_TURN} new record" in publish(anchor, remote)
    assert published_anchor(remote) == lines(anchor)
    assert len(commits(remote)) == 1


def test_later_publishes_append_commits_and_never_rewrite(system, remote):
    kernel, log, anchor, turns = system
    turns(2)
    publish(anchor, remote)
    turns(2)
    assert f"published {2 * ENTRIES_PER_TURN} new record" in publish(anchor, remote)
    assert published_anchor(remote) == lines(anchor) and len(lines(anchor)) == 4 * ENTRIES_PER_TURN
    assert len(commits(remote)) == 2


def test_publishing_twice_with_nothing_new_makes_no_commit(system, remote):
    kernel, log, anchor, turns = system
    turns(2)
    publish(anchor, remote)
    assert "already up to date" in publish(anchor, remote)
    assert len(commits(remote)) == 1


def test_a_rewritten_local_anchor_is_refused_and_the_remote_is_untouched(system, remote):
    kernel, log, anchor, turns = system
    turns(3)
    publish(anchor, remote)
    before = published_anchor(remote)
    forged = lines(anchor)
    forged[1] = forged[1].replace("a", "b", 3)
    anchor.write_text("\n".join(forged) + "\n")
    with pytest.raises(AnchorGitError, match="does not continue"):
        publish(anchor, remote)
    assert published_anchor(remote) == before and len(commits(remote)) == 1


def test_a_shortened_local_anchor_is_refused(system, remote):
    kernel, log, anchor, turns = system
    turns(3)
    publish(anchor, remote)
    anchor.write_text("\n".join(lines(anchor)[:2]) + "\n")
    with pytest.raises(AnchorGitError, match="does not continue"):
        publish(anchor, remote)


def test_publish_with_a_log_refuses_a_log_that_fails_its_anchor(system, remote):
    kernel, log, anchor, turns = system
    turns(3)
    log.write_text("\n".join(lines(log)[:-1]) + "\n")  # only the very last entry (an outcome) deleted
    with pytest.raises(AnchorGitError, match="does not match its own anchor"):
        publish(anchor, remote, log=log)
    assert published_anchor(remote) is None  # nothing was published


def test_an_anchor_with_no_records_is_not_published(tmp_path, remote):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    with pytest.raises(AnchorGitError, match="no anchor records"):
        publish(empty, remote)


def test_verify_passes_for_an_untouched_log(system, remote):
    kernel, log, anchor, turns = system
    turns(3)
    publish(anchor, remote)
    assert f"log verified: {3 * ENTRIES_PER_TURN} receipts" in verify(log, remote)


def test_the_published_copy_catches_a_log_and_anchor_that_were_both_edited(system, remote):
    """The point of the helper: the attacker deletes the newest receipt AND edits the local
    anchor so the local check passes. Only the published copy still says what was there."""
    kernel, log, anchor, turns = system
    turns(3)
    publish(anchor, remote)
    log.write_text("\n".join(lines(log)[:-1]) + "\n")  # drop just the last outcome...
    anchor.write_text("\n".join(lines(anchor)[:-1]) + "\n")  # ...and the matching anchor record
    assert kernel.verify() is True  # the local check is fooled
    with pytest.raises(AnchorGitError, match="deleted"):
        verify(log, remote)


def test_verify_with_nothing_published_is_an_error_not_a_pass(system, remote):
    kernel, log, anchor, turns = system
    turns(1)
    with pytest.raises(AnchorGitError, match="nothing published"):
        verify(log, remote)


def test_a_rejected_push_is_reported_and_nothing_is_forced(system, remote):
    kernel, log, anchor, turns = system
    turns(2)
    hook = Path(remote) / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\necho rejected-by-test >&2\nexit 1\n")
    hook.chmod(0o755)
    with pytest.raises(AnchorGitError, match="rejected-by-test"):
        publish(anchor, remote)


def test_the_helper_never_force_pushes():
    source = Path(anchor_git.__file__).read_text()
    assert "--force" not in source and '"-f"' not in source and "+HEAD" not in source


def test_command_line_exit_codes(system, remote, capsys):
    kernel, log, anchor, turns = system
    turns(2)
    assert anchor_git.main(["publish", "--anchor", str(anchor), "--repo", remote, "--log", str(log)]) == 0
    assert anchor_git.main(["verify", "--log", str(log), "--repo", remote]) == 0
    log.write_text("\n".join(lines(log)[:1]) + "\n")
    assert anchor_git.main(["verify", "--log", str(log), "--repo", remote]) == 1
    assert "deleted" in capsys.readouterr().err
