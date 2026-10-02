"""The operator screen in a real Chromium, via Playwright (skipped if either is missing)."""

import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

from nova.ick import IckGate, IckGatedProvider, KernelRefusal, _find_binary
from nova.ick_approvals import ApprovalStore
from nova.operator_ui import OperatorConfig, make_server

HERE = Path(__file__).resolve().parent
HOSTILE = '<img src=x onerror="window.__xss=1">'

try:
    _find_binary(None)
except KernelRefusal:
    pytest.skip("infinityctl not built", allow_module_level=True)
if not shutil.which("node"):
    pytest.skip("node is not installed", allow_module_level=True)
probe = subprocess.run(["node", "-e", "require.resolve('playwright')"], capture_output=True)
if probe.returncode != 0 and not os.environ.get("NODE_PATH"):
    pytest.skip("playwright is not installed for node (set NODE_PATH)", allow_module_level=True)


class Fake:
    model, provider_id = "m", HOSTILE  # the hostile text arrives as the request's target

    def chat_completion(self, governed_request):
        return {}


def test_the_screen_works_in_a_real_browser_and_hostile_text_stays_inert(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-approve-v1",
                                  "denied_effects": [], "effects_requiring_approval": ["read"]}))
    log, anchor = tmp_path / "log" / "r.jsonl", tmp_path / "safe" / "a.jsonl"
    store = ApprovalStore(tmp_path / "human" / "approvals.jsonl", tmp_path / "state")
    provider = IckGatedProvider(Fake(), IckGate(policy, log=log, anchor=anchor, approvals=store))
    with pytest.raises(KernelRefusal):
        provider.chat_completion({"messages": [{"role": "user", "content": "hi"}]})
    with pytest.raises(KernelRefusal):
        provider.chat_completion({"messages": [{"role": "user", "content": "a second request"}]})

    status = tmp_path / "publish-status.json"
    status.write_text(json.dumps({
        "last_success_at": int(__import__("time").time()) - 90, "published_records": 1,
        "consecutive_failures": 2, "integrity_failure": False, "last_error": "push failed " + HOSTILE}))
    server, token = make_server(OperatorConfig(store.approvals_file, tmp_path / "state", log=log, anchor=anchor,
                                               publish_status=status))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    shots = Path(os.environ.get("OPERATOR_SHOTS", tmp_path / "shots"))
    shots.mkdir(parents=True, exist_ok=True)
    try:
        done = subprocess.run(
            ["node", str(HERE / "browser" / "operator_check.cjs"),
             f"http://127.0.0.1:{server.server_address[1]}", token, str(shots), HOSTILE],
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "NODE_PATH": os.environ.get("NODE_PATH") or subprocess.run(
                ["npm", "root", "-g"], capture_output=True, text=True).stdout.strip()})
    finally:
        server.shutdown()
    assert done.returncode == 0, done.stderr[-1500:]
    r = json.loads(done.stdout.strip().splitlines()[-1])

    assert r["errors"] == [], r["errors"]  # includes any Content-Security-Policy violation
    assert r["unauthorized"] == 1  # only the deliberate wrong-token probe
    assert r["login_shown"] and r["app_hidden_without_token"]
    assert "token" in r["wrong_token_message"].lower()
    assert r["pending_rows"] == 2
    assert r["hostile_rendered_literally"] is True and HOSTILE in r["target_text"]
    assert r["injected_elements"] == 0 and r["xss_ran"] is False
    assert r["hash_after_signin"] == ""  # the token was removed from the address bar
    assert any("Receipt log verified" in chip for chip in r["chips"]), r["chips"]
    assert any("signatures: not checked" in chip for chip in r["chips"]), r["chips"]  # no keys configured here
    failing = [chip for chip in r["chips"] if "anchor publishing failing (2 in a row)" in chip]
    assert failing and HOSTILE in failing[0], r["chips"]  # shown as text, not interpreted
    assert any("anchor published" in chip for chip in r["chips"]), r["chips"]
    assert r["injected_in_chips"] == 0
    assert r["phone_horizontal_overflow"] is False
    assert r["pending_after_cancel"] == 1  # cancelling the reason prompt denied nothing
    assert [d.split(":")[0] for d in r["dialogs"]] == ["confirm", "confirm", "prompt", "confirm", "prompt"]
    assert "Approve this request?" in r["dialogs"][0] and "Deny this request?" in r["dialogs"][1]
    assert r["pending_hidden_after"] is False and r["pending_rows_before_deny"] == 1 and r["approved_rows"] == 1
    assert r["pending_hidden_after_deny"] is True and r["denied_rows"] == 1
    assert r["denied_by"] == "operator" and r["denied_reason"] == "too risky <b>x</b>"  # literal text
    assert r["injected_in_denied"] == 0
    assert len(store.denials()) == 1 and store.denials()[0]["reason"] == "too risky <b>x</b>"
    assert r["published_button_hidden"] is True  # no anchor repository is configured
    assert r["phone_pending_table_hidden"] is True and r["phone_published_button_hidden"] is True
    assert store.approvals()[0]["approved_by"] == "operator" == r["approved_by"]
