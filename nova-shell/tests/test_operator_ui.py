import http.client
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from nova import operator_ui
from nova.ick import IckGate, IckGatedProvider, KernelRefusal, _find_binary
from nova.ick_approvals import ApprovalStore
from nova.operator_ui import OperatorConfig, make_server

try:
    _find_binary(None)
except KernelRefusal:
    pytest.skip("infinityctl not built (run `cargo build`)", allow_module_level=True)


class Fake:
    model, provider_id, calls = "m", "fake", 0

    def chat_completion(self, governed_request):
        self.calls += 1
        return {"completion": {"id": "c", "model": "m", "created": 1, "choices": [
            {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}]},
            "receipt": {}}


class Operator:
    def __init__(self, tmp_path, nova_url=None):
        self.dir = tmp_path
        self.policy = tmp_path / "policy.json"
        self.policy.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-approve-v1",
                                           "denied_effects": [], "effects_requiring_approval": ["read"]}))
        self.log, self.anchor = tmp_path / "log" / "r.jsonl", tmp_path / "safe" / "a.jsonl"
        self.store = ApprovalStore(tmp_path / "human" / "approvals.jsonl", tmp_path / "state")
        self.config = OperatorConfig(self.store.approvals_file, tmp_path / "state", log=self.log,
                                     anchor=self.anchor, nova_url=nova_url)
        self.server, self.token = make_server(self.config)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.provider = IckGatedProvider(
            Fake(), IckGate(self.policy, log=self.log, anchor=self.anchor, approvals=self.store))

    def ask(self, text="hello", target_name=None):
        if target_name:
            self.provider._inner.provider_id = target_name
        try:
            self.provider.chat_completion({"messages": [{"role": "user", "content": text}]})
        except KernelRefusal as err:
            return err

    def call(self, method, path, body=None, *, token=True, headers=None, host=None, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        send = {"Host": host or f"127.0.0.1:{self.port}", **(headers or {})}
        if token is True:
            send["Authorization"] = f"Bearer {self.token}"
        elif token:
            send["Authorization"] = f"Bearer {token}"
        payload = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        if payload is not None:
            send["Content-Type"] = "application/json"
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for key, value in send.items():
            conn.putheader(key, value)
        if payload is not None:
            conn.putheader("Content-Length", str(len(payload)))
        conn.endheaders(payload)
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response.status, dict(response.getheaders()), data


@pytest.fixture
def op(tmp_path):
    operator = Operator(tmp_path)
    yield operator
    operator.server.shutdown()


def state(op):
    status, _, data = op.call("GET", "/api/state")
    assert status == 200
    return json.loads(data)


# --- who may talk to it ---------------------------------------------------------------------

def test_the_page_is_public_but_carries_no_data_and_a_strict_policy(op):
    op.ask(target_name="<script>alert('secret-target')</script>")
    status, headers, body = op.call("GET", "/", token=False)
    assert status == 200 and b"secret-target" not in body and b"hello" not in body
    csp = headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp and "unsafe-inline" not in csp
    nonce = re.search(r"script-src 'nonce-([^']+)'", csp).group(1)
    assert f'nonce="{nonce}"'.encode() in body
    assert headers["Cache-Control"] == "no-store" and headers["X-Content-Type-Options"] == "nosniff"
    _, headers2, _ = op.call("GET", "/", token=False)
    assert headers2["Content-Security-Policy"] != csp  # a fresh nonce every time


@pytest.mark.parametrize("token", [False, "wrong", "", "x" * 500])
def test_data_and_actions_need_the_token(op, token):
    assert op.call("GET", "/api/state", token=token)[0] == 401
    assert op.call("POST", "/api/approve", {"proposal_hash": "h"}, token=token)[0] == 401
    assert op.call("POST", "/api/check-published", {}, token=token)[0] == 401


def test_a_token_in_the_url_never_authenticates(op):
    status, _, body = op.call("GET", f"/api/state?token={op.token}", token=False)
    assert status in (401, 404) and b"pending" not in body


def test_a_foreign_host_header_is_refused_to_stop_dns_rebinding(op):
    assert op.call("GET", "/", token=False, host="evil.example")[0] == 403
    assert op.call("GET", "/api/state", host=f"evil.example:{op.port}")[0] == 403
    assert op.call("GET", "/api/state", host=f"localhost:{op.port}")[0] == 200


def test_a_foreign_origin_is_refused_so_other_sites_cannot_drive_it(op):
    op.ask()
    h = state(op)["pending"][0]["proposal_hash"]
    status, _, _ = op.call("POST", "/api/approve", {"proposal_hash": h}, headers={"Origin": "https://evil.example"})
    assert status == 403
    assert state(op)["approved"] == []  # nothing was approved
    status, _, _ = op.call("POST", "/api/approve", {"proposal_hash": h}, headers={"Origin": f"http://127.0.0.1:{op.port}"})
    assert status == 200


def test_it_grants_no_cross_origin_access(op):
    _, headers, _ = op.call("GET", "/api/state")
    assert not any(k.lower().startswith("access-control") for k in headers)
    assert op.call("OPTIONS", "/api/approve", token=False)[0] in (501, 405, 404)


def test_it_refuses_to_listen_beyond_loopback(tmp_path):
    for host in ("0.0.0.0", "192.168.1.5", ""):
        with pytest.raises(ValueError, match="loopback"):
            make_server(OperatorConfig(tmp_path / "a", tmp_path / "s"), host=host)


def test_the_launcher_needs_a_place_for_approvals(monkeypatch):
    monkeypatch.delenv("NOVA_ICK_APPROVALS", raising=False)
    assert operator_ui.main([]) == 2
    assert operator_ui.main(["--approvals", "x", "--host", "0.0.0.0"]) == 2


# --- what it shows ---------------------------------------------------------------------------

def test_it_lists_what_is_waiting_and_whether_the_log_verifies(op):
    assert state(op)["pending"] == [] and state(op)["log"]["present"] is False
    op.ask("first")
    s = state(op)
    assert len(s["pending"]) == 1 and s["pending"][0]["effect"] == "read"
    assert s["log"]["present"] and s["log"]["verified"] is True and s["log"]["anchored"] is True
    assert s["log"]["recent"][0]["verdict"] == "await_human_approval"
    assert s["nova"]["status"] == "not configured"


def test_it_reports_a_log_that_fails_its_anchor(op):
    for text in ("a", "b", "c"):
        op.ask(text)
    lines = op.log.read_text().splitlines()
    op.log.write_text("\n".join(lines[:-1]) + "\n")  # delete the newest receipt
    log = state(op)["log"]
    assert log["verified"] is False and "deleted" in log["message"]


def test_it_shows_whether_nova_is_up(tmp_path):
    class Healthy(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a): pass

    nova = HTTPServer(("127.0.0.1", 0), Healthy)
    threading.Thread(target=nova.serve_forever, daemon=True).start()
    (tmp_path / "up").mkdir()
    (tmp_path / "down").mkdir()
    up = Operator(tmp_path / "up", nova_url=f"http://127.0.0.1:{nova.server_port}")
    down = Operator(tmp_path / "down", nova_url="http://127.0.0.1:9")
    try:
        assert state(up)["nova"]["status"] == "ok"
        assert state(down)["nova"]["status"] == "unreachable"
    finally:
        for o in (up, down):
            o.server.shutdown()
        nova.shutdown()


def test_hostile_text_stays_data_and_never_becomes_page(op):
    payload = "<img src=x onerror=alert(1)>"
    op.ask(target_name=payload)
    pending = state(op)["pending"][0]
    assert payload in pending["target"]
    _, _, page = op.call("GET", "/", token=False)
    assert payload.encode() not in page
    assert b"innerHTML" not in page and b"document.write" not in page and b"eval(" not in page


# --- what it can do --------------------------------------------------------------------------

def test_approving_lets_the_request_through_exactly_once(op):
    err = op.ask("do the thing")
    assert err.code == "KERNEL_AWAITING_APPROVAL"
    status, _, data = op.call("POST", "/api/approve", {"proposal_hash": err.proposal_hash, "expires_in": 600,
                                                       "uses": 1, "approved_by": "alice"})
    assert status == 200 and json.loads(data)["approval_id"].startswith("approval-")
    s = state(op)
    assert s["pending"] == [] and s["approved"][0]["approved_by"] == "alice" and s["approved"][0]["remaining"] == 1
    assert op.provider.chat_completion({"messages": [{"role": "user", "content": "do the thing"}]})["ick"]["approved_by"] == "alice"
    assert op.ask("do the thing").code == "KERNEL_AWAITING_APPROVAL"  # the single use is spent
    assert state(op)["approved"] == []


def test_denying_refuses_the_request_for_good_and_shows_in_the_list(op):
    err = op.ask("do the thing")
    status, _, data = op.call("POST", "/api/deny", {"proposal_hash": err.proposal_hash, "reason": "nope",
                                                    "denied_by": "alice"})
    assert status == 200 and json.loads(data)["denial_id"].startswith("denial-")
    s = state(op)
    assert s["pending"] == [] and s["approved"] == []
    assert [(d["denied_by"], d["reason"]) for d in s["denied"]] == [("alice", "nope")]
    assert op.ask("do the thing").code == "KERNEL_DENIED_BY_HUMAN"
    assert op.call("POST", "/api/approve", {"proposal_hash": err.proposal_hash})[0] == 400  # cannot be undone here
    assert op.call("POST", "/api/deny", {"proposal_hash": err.proposal_hash})[0] == 400


def test_denying_takes_back_an_approval_already_given(op):
    h = op.ask("do the thing").proposal_hash
    assert op.call("POST", "/api/approve", {"proposal_hash": h, "uses": 5})[0] == 200
    assert op.call("POST", "/api/deny", {"proposal_hash": h})[0] == 200
    assert state(op)["approved"] == []
    assert op.ask("do the thing").code == "KERNEL_DENIED_BY_HUMAN"


def test_deny_input_is_checked_by_the_server(op):
    h = op.ask().proposal_hash
    bad = [{"proposal_hash": h, "reason": "x" * 201}, {"proposal_hash": h, "reason": 7},
           {"proposal_hash": h, "denied_by": "<script>"}, {"proposal_hash": h, "denied_by": "x" * 65},
           {"proposal_hash": ""}, {"proposal_hash": 7}, {}]
    for body in bad:
        assert op.call("POST", "/api/deny", body)[0] == 400, body
    assert not op.store.denials_file.exists()
    assert op.call("POST", "/api/deny", {"proposal_hash": "sha3-256:made-up"})[0] == 404
    assert op.call("POST", "/api/deny", {"proposal_hash": h}, token=False)[0] == 401


def test_approval_limits_are_enforced_by_the_server(op):
    h = op.ask().proposal_hash
    bad = [{"proposal_hash": h, "expires_in": 5}, {"proposal_hash": h, "expires_in": 10**9},
           {"proposal_hash": h, "uses": 0}, {"proposal_hash": h, "uses": 101}, {"proposal_hash": h, "uses": True},
           {"proposal_hash": h, "uses": "1"}, {"proposal_hash": h, "expires_in": "600"},
           {"proposal_hash": h, "approved_by": "<script>"}, {"proposal_hash": h, "approved_by": "x" * 65},
           {"proposal_hash": ""}, {"proposal_hash": 7}, {}]
    for body in bad:
        assert op.call("POST", "/api/approve", body)[0] == 400, body
    assert not op.store.approvals_file.exists()  # none of them wrote anything


def test_it_cannot_approve_something_that_was_never_requested(op):
    status, _, data = op.call("POST", "/api/approve", {"proposal_hash": "sha3-256:made-up"})
    assert status == 404 and not op.store.approvals_file.exists()


def test_bad_requests_are_rejected_cleanly(op):
    assert op.call("POST", "/api/approve", raw=b"not json")[0] == 400
    assert op.call("POST", "/api/approve", raw=b"[1,2]")[0] == 400
    assert op.call("POST", "/api/approve", raw=b"{" + b" " * 5000 + b"}")[0] == 413
    assert op.call("POST", "/api/nope", {})[0] == 404
    assert op.call("GET", "/api/nope")[0] == 404
    assert op.call("POST", "/api/check-published", {})[0] == 400  # no anchor repository configured


def test_the_nova_api_still_has_no_route_for_approving():
    from nova.api import app

    assert not [r.path for r in app.routes if "approv" in getattr(r, "path", "").lower()]


def test_it_shows_outcomes_times_and_allows_that_have_none(tmp_path):
    import re

    policy = tmp_path / "open.json"
    policy.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-open-v1",
                                  "denied_effects": [], "effects_requiring_approval": []}))
    (tmp_path / "x").mkdir()
    operator = Operator(tmp_path / "x")
    try:
        gate = IckGate(policy, log=operator.log, anchor=operator.anchor)
        IckGatedProvider(Fake(), gate).chat_completion({"messages": [{"role": "user", "content": "hi"}]})
        gate.check(target="fake:m", governed_request={"messages": [{"role": "user", "content": "unfinished"}]})
        log = state(operator)["log"]
        assert log["verified"] and log["count"] == 3 and log["outcomes"] == 1
        assert log["allows_without_outcome"] == 1  # the call that never reported back
        newest_first = [row["verdict"] for row in log["recent"]]
        assert newest_first == ["allow", "outcome: completed", "allow"]
        assert all(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", row["issued_at"]) for row in log["recent"])
    finally:
        operator.server.shutdown()
