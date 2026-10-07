"""Executor mode: bind a call to an allow, and refuse the attacks that break that binding.

The signer and the witness run in this process, with two different keys. That is not an
account-separation probe. Nothing here claims the target's state was observed.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "verifier"))
import ickverify  # noqa: E402

import pytest

from runtime.call_binding import bind_proposal, derive
from runtime.ick_service import Service, ServiceError
from runtime.kernel import Kernel, KernelError, find_binary
from runtime.witness import Witness, dispatch_https

try:
    BINARY = find_binary()
except KernelError:
    BINARY = None

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "verifier" / "ickverify.py"


def proposal(effect, target, action="call"):
    return {
        "version": "infinity.proposal.v1",
        "proposal_id": "p-bind",
        "actor": {"kind": "agent", "id": "nova"},
        "action": action,
        "target": target,
        "effect": effect,
        "risk": "low",
        "requires_human_approval": False,
        "policy_version": "policy-test-v1",
        "payload": {},
        "evidence_refs": [],
    }


def https_call(method, host, port, path, query="", body=None, authorization=None):
    call = {
        "shape": "https_request",
        "method": method,
        "scheme": "http",
        "host": host,
        "port": port,
        "path": path,
    }
    if query:
        call["query"] = query
    if body is not None:
        call["body"] = body
    if authorization is not None:
        call["headers"] = {"Authorization": authorization}
        call["authorization_present"] = True
    return call


def keygen(directory, name):
    private, public = directory / f"{name}.priv", directory / f"{name}.pub"
    subprocess.run(
        [BINARY, "keygen", "--out", str(private), "--public-out", str(public)],
        check=True,
        capture_output=True,
    )
    return private, public


class World:
    def __init__(self, tmp_path):
        self.dir = tmp_path
        self.signer_key, self.signer_pub = keygen(tmp_path, "signer")
        self.witness_key, self.witness_pub = keygen(tmp_path, "witness")
        policy = tmp_path / "policy.json"
        policy.write_text(json.dumps({
            "version": "infinity.policy.v1",
            "policy_id": "policy-test-v1",
            "denied_effects": [],
            "effects_requiring_approval": [],
            "risks_requiring_approval": [],
        }))
        self.policy = policy
        self.log = tmp_path / "receipts.jsonl"
        self.anchor = tmp_path / "anchor.jsonl"
        self.witness_log = tmp_path / "witness.jsonl"
        kernel = Kernel(policy, self.log, binary=BINARY, anchor=self.anchor, sign_key=self.signer_key)
        self.service = Service(kernel)
        self.seen = []

    def allow(self, call, effect=None, target=None, call_digest=None):
        derived = derive(call)
        body = proposal(
            derived.effect if effect is None else effect,
            derived.target if target is None else target,
        )
        if call_digest is not None:
            body["call_digest"] = call_digest
        return self.service.handle({"op": "evaluate", "proposal": body, "call": call})

    def witness(self, dispatch=None, clock=None, allow_ttl=3600):
        if dispatch is None:
            def dispatch(bound):
                text = self.witness_log.read_text(encoding="utf-8")
                assert '"status":"started"' in text
                self.seen.append(bound.method or bound.tool)
                return b"ok"

        return Witness(
            binary=BINARY,
            receipt_log=self.log,
            witness_log=self.witness_log,
            witness_key=self.witness_key,
            receipt_trusted_keys=self.signer_pub,
            receipt_anchor=self.anchor,
            dispatch=dispatch,
            allow_ttl=allow_ttl,
            clock=clock,
        )


def _issued(text):
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


def test_method_and_host_case_do_not_change_the_digest_and_the_authorization_value_is_not_in_it():
    plain = https_call("GET", "example.test", 443, "/x")
    same = https_call("get", "Example.Test", 443, "/x")
    other_path = https_call("GET", "example.test", 443, "/X")
    other_body = https_call("POST", "example.test", 443, "/x", body="one")
    changed_body = https_call("POST", "example.test", 443, "/x", body="two")
    with_secret = https_call("GET", "example.test", 443, "/x", authorization="secret-a")
    other_secret = https_call("GET", "example.test", 443, "/x", authorization="secret-b")
    assert derive(plain).call_digest == derive(same).call_digest
    assert derive(plain).call_digest != derive(other_path).call_digest
    assert derive(other_body).call_digest != derive(changed_body).call_digest
    assert derive(with_secret).call_digest == derive(other_secret).call_digest
    assert derive(with_secret).call_digest != derive(plain).call_digest
    assert derive(plain).effect == "read"
    assert derive(other_body).effect == "write"
    tool = {"shape": "local_model_tool", "tool": "explain", "arguments": {"b": 1, "a": 2}}
    again = {"shape": "local_model_tool", "tool": "explain", "arguments": {"a": 2, "b": 1}}
    assert derive(tool).call_digest == derive(again).call_digest
    assert derive(tool).effect == "read"
    assert derive({"shape": "local_model_tool", "tool": "code", "arguments": {}}).effect == "write"


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_allow_a_read_then_execute_a_write_is_a_mismatch_and_the_read_still_runs(tmp_path):
    world = World(tmp_path)
    get_call = https_call("GET", "example.test", 443, "/status")
    post_call = https_call("POST", "example.test", 443, "/status", body="write")
    allowed = world.allow(get_call)
    assert allowed["decision"]["verdict"] == "allow"
    receipt = allowed["receipt"]
    assert receipt["call_digest"] == derive(get_call).call_digest
    witness = world.witness()
    mismatch = witness.execute(post_call, receipt["receipt_id"])
    assert mismatch.dispatched is False and mismatch.divergence == "mismatch"
    assert world.seen == []
    assert mismatch.entries[0]["key_id"] != receipt["key_id"]
    done = witness.execute(get_call, receipt["receipt_id"])
    assert done.dispatched is True and done.status == "completed" and done.body == b"ok"
    assert world.seen == ["GET"]
    checked = subprocess.run(
        [BINARY, "witness-verify", "--log", str(world.witness_log), "--trusted-keys", str(world.witness_pub)],
        capture_output=True, text=True,
    )
    assert checked.returncode == 0, checked.stderr
    wrong_key = subprocess.run(
        [BINARY, "witness-verify", "--log", str(world.witness_log), "--trusted-keys", str(world.signer_pub)],
        capture_output=True, text=True,
    )
    assert wrong_key.returncode != 0
    verified = subprocess.run(
        [sys.executable, str(VERIFIER), str(world.log), "--anchor", str(world.anchor),
         "--trusted-keys", str(world.signer_pub), "--require-signatures"],
        capture_output=True, text=True,
    )
    assert verified.returncode == 0, verified.stderr + verified.stdout
    try:
        import jsonschema
    except ImportError:
        jsonschema = None
    if jsonschema is not None:
        schema = json.loads((ROOT / "contracts" / "receipt.v2.json").read_text())
        jsonschema.validate(receipt, schema)


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_one_allow_cannot_be_replayed(tmp_path):
    world = World(tmp_path)
    call = https_call("GET", "example.test", 443, "/once")
    receipt = world.allow(call)["receipt"]
    witness = world.witness()
    first = witness.execute(call, receipt["receipt_id"])
    second = witness.execute(call, receipt["receipt_id"])
    assert first.status == "completed" and first.dispatched is True
    assert second.divergence == "reused" and second.dispatched is False
    assert world.seen == ["GET"]


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_describing_a_write_as_a_read_is_denied_and_that_receipt_cannot_dispatch(tmp_path):
    world = World(tmp_path)
    post = https_call("POST", "example.test", 443, "/secret", body="x")
    derived = derive(post)
    stated = proposal("read", "http://example.test:443/harmless")
    stated["call_digest"] = derived.call_digest
    out = world.service.handle({"op": "evaluate", "proposal": stated, "call": post})
    assert out["decision"]["verdict"] == "deny"
    assert out["decision"]["reason_codes"] == ["DESCRIPTION_DISAGREEMENT"]
    bound = bind_proposal(stated, post)
    assert bound["effect"] == "write" and bound["target"] == derived.target
    assert bound["payload"]["binding_fault"] == "DESCRIPTION_DISAGREEMENT"
    assert world.service.kernel.proposal_hash(bound) == out["decision"]["proposal_hash"]
    assert world.service.kernel.proposal_hash(stated) != out["decision"]["proposal_hash"]
    witness = world.witness()
    refused = witness.execute(post, out["receipt"]["receipt_id"])
    assert refused.divergence == "unauthorized" and refused.dispatched is False
    assert world.seen == []


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_a_matching_description_with_the_wrong_digest_is_denied(tmp_path):
    world = World(tmp_path)
    call = https_call("GET", "example.test", 443, "/a")
    wrong = "sha256:" + ("ab" * 32)
    out = world.allow(call, call_digest=wrong)
    assert out["decision"]["verdict"] == "deny"
    assert out["decision"]["reason_codes"] == ["DESCRIPTION_DISAGREEMENT"]
    assert out["receipt"]["call_digest"] == derive(call).call_digest


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_an_unknown_call_shape_is_denied_and_not_allowed(tmp_path):
    world = World(tmp_path)
    out = world.service.handle({
        "op": "evaluate",
        "proposal": proposal("read", "t"),
        "call": {"shape": "shell", "cmd": "id"},
    })
    assert out["decision"]["verdict"] == "deny"
    assert out["decision"]["reason_codes"] == ["UNKNOWN_CALL_SHAPE"]
    assert "call_digest" not in out["receipt"]
    options = https_call("GET", "example.test", 443, "/a")
    options["method"] = "OPTIONS"
    denied = world.service.handle({"op": "evaluate", "proposal": proposal("read", "t"), "call": options})
    assert denied["decision"]["reason_codes"] == ["UNKNOWN_CALL_SHAPE"]
    allowed = world.allow(https_call("GET", "example.test", 443, "/known"))
    witness = world.witness()
    unknown_at_execute = witness.execute({"shape": "shell", "cmd": "id"}, allowed["receipt"]["receipt_id"])
    assert unknown_at_execute.divergence == "mismatch" and unknown_at_execute.dispatched is False
    assert world.seen == []


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_a_local_model_tool_write_described_as_a_read_is_denied(tmp_path):
    world = World(tmp_path)
    call = {"shape": "local_model_tool", "tool": "code", "arguments": {"path": "a.py"}}
    out = world.service.handle({
        "op": "evaluate",
        "proposal": proposal("read", "local-model-tool:explain"),
        "call": call,
    })
    assert out["decision"]["verdict"] == "deny"
    assert out["decision"]["reason_codes"] == ["DESCRIPTION_DISAGREEMENT"]
    assert out["receipt"]["call_digest"] == derive(call).call_digest


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_without_a_call_the_signer_still_trusts_the_description(tmp_path):
    world = World(tmp_path)
    out = world.service.handle({"op": "evaluate", "proposal": proposal("write", "anywhere")})
    assert out["decision"]["verdict"] == "allow"
    assert "call_digest" not in out["receipt"]


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_a_call_that_is_not_an_object_is_refused_before_a_decision(tmp_path):
    world = World(tmp_path)
    with pytest.raises(ServiceError, match="call must be an object"):
        world.service.handle({"op": "evaluate", "proposal": proposal("read", "t"), "call": "nope"})
    assert not world.log.exists()


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_an_expired_allow_is_late_and_a_broken_log_is_unauthorized(tmp_path):
    world = World(tmp_path)
    call = https_call("GET", "example.test", 443, "/late")
    receipt = world.allow(call)["receipt"]
    issued = _issued(receipt["issued_at"])
    late = world.witness(clock=lambda: issued + 3601).execute(call, receipt["receipt_id"])
    assert late.divergence == "late" and late.dispatched is False
    assert world.seen == []
    text = world.log.read_text(encoding="utf-8")
    flipped = text.replace("sha3-256:", "sha3-255:", 1)
    assert flipped != text
    world.log.write_text(flipped)
    refused = world.witness(clock=lambda: issued + 10).execute(call, receipt["receipt_id"])
    assert refused.divergence == "unauthorized" and refused.dispatched is False
    assert world.seen == []


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_a_dispatch_failure_consumes_the_allow(tmp_path):
    world = World(tmp_path)
    call = https_call("GET", "example.test", 443, "/down")
    receipt = world.allow(call)["receipt"]

    def boom(bound):
        assert '"status":"started"' in world.witness_log.read_text(encoding="utf-8")
        raise RuntimeError("target down")

    witness = world.witness(dispatch=boom)
    failed = witness.execute(call, receipt["receipt_id"])
    assert failed.dispatched is True and failed.status == "failed"
    assert failed.entries[0]["status"] == "started"
    again = witness.execute(call, receipt["receipt_id"])
    assert again.divergence == "reused" and again.dispatched is False


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_a_real_localhost_get_is_sent_and_a_mismatched_post_is_not(tmp_path):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(("GET", self.path))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"pong")

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            seen.append(("POST", self.path))
            self.send_response(200)
            self.end_headers()

        def log_message(self, fmt, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        world = World(tmp_path)
        get_call = https_call("GET", "127.0.0.1", port, "/ping")
        post_call = https_call("POST", "127.0.0.1", port, "/ping", body="no")
        receipt = world.allow(get_call)["receipt"]
        witness = world.witness(dispatch=dispatch_https)
        bad = witness.execute(post_call, receipt["receipt_id"])
        good = witness.execute(get_call, receipt["receipt_id"])
        assert bad.divergence == "mismatch" and bad.dispatched is False
        assert good.status == "completed" and good.body == b"pong"
        assert seen == [("GET", "/ping")]
    finally:
        server.shutdown()
        server.server_close()


def test_http_dispatch_does_not_follow_redirects():
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/landed")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"landed")

        def log_message(self, fmt, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        body = dispatch_https(derive(https_call("GET", "127.0.0.1", port, "/start")))
    finally:
        server.shutdown()
        server.server_close()
    assert seen == ["/start"]
    assert body == b""


def test_ickverify_recomputes_the_same_call_digest():
    plain = https_call("GET", "example.test", 443, "/x")
    same = https_call("get", "Example.Test", 443, "/x")
    with_secret = https_call("GET", "example.test", 443, "/x", authorization="secret-a")
    other_secret = https_call("GET", "example.test", 443, "/x", authorization="secret-b")
    tool = {"shape": "local_model_tool", "tool": "explain", "arguments": {"b": 1, "a": 2}}
    again = {"shape": "local_model_tool", "tool": "explain", "arguments": {"a": 2, "b": 1}}
    for call in (plain, same, with_secret, other_secret, tool, again):
        assert ickverify.call_digest(call) == derive(call).call_digest
    assert ickverify.call_digest(plain) == ickverify.call_digest(same)
    assert ickverify.call_digest(with_secret) == ickverify.call_digest(other_secret)
    assert ickverify.call_digest(with_secret) != ickverify.call_digest(plain)
    assert ickverify.call_digest(tool) == ickverify.call_digest(again)


def _allow_receipt(tmp_path, *, digest):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({
        "version": "infinity.policy.v1", "policy_id": "policy-test-v1",
        "denied_effects": [], "effects_requiring_approval": [],
    }))
    log = tmp_path / "receipts.jsonl"
    body = proposal("read", "stated-target")
    if digest is not None:
        body["call_digest"] = digest
    Kernel(policy, log, binary=BINARY).evaluate(body)
    receipt = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    return log, receipt


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_a_forged_call_digest_fails_verify(tmp_path):
    call = https_call("GET", "example.test", 80, "/real")
    forged = "sha256:" + ("ab" * 32)
    assert forged != derive(call).call_digest
    log, receipt = _allow_receipt(tmp_path, digest=forged)
    report = ickverify.verify(log.read_text(encoding="utf-8"), call_text=json.dumps({
        "receipt_id": receipt["receipt_id"], "call": call,
    }))
    assert report["ok"] is False
    assert any("forged call_digest" in error for error in report["errors"])


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_an_omitted_call_digest_on_a_bound_call_fails_verify(tmp_path):
    call = https_call("POST", "example.test", 80, "/real", body="x")
    log, receipt = _allow_receipt(tmp_path, digest=None)
    assert "call_digest" not in receipt
    report = ickverify.verify(log.read_text(encoding="utf-8"), call_text=json.dumps({
        "receipt_id": receipt["receipt_id"], "call": call,
    }))
    assert report["ok"] is False
    assert any("omitted call_digest" in error for error in report["errors"])


def _verify_join(log, witness_log, witness_keys, call=None, receipt_id=None):
    command = [
        sys.executable, str(VERIFIER), str(log),
        "--witness-log", str(witness_log),
        "--witness-keys", str(witness_keys),
        "--json",
    ]
    if call is not None:
        bind = log.parent / "call.json"
        bind.write_text(json.dumps({"receipt_id": receipt_id, "call": call}), encoding="utf-8")
        command += ["--call", str(bind)]
    done = subprocess.run(command, capture_output=True, text=True)
    report = json.loads(done.stdout) if done.stdout.strip().startswith("{") else {"ok": False, "errors": [done.stderr]}
    return done.returncode, report


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_witness_join_reports_mismatch_unauthorized_reused_late_and_missing(tmp_path):
    call = https_call("GET", "example.test", 80, "/join")
    world = World(tmp_path)
    allowed = world.allow(call)
    receipt_id = allowed["receipt"]["receipt_id"]
    empty = tmp_path / "empty-witness.jsonl"
    empty.write_text("", encoding="utf-8")
    code, report = _verify_join(world.log, empty, world.witness_pub)
    assert code == 1 and report["ok"] is False
    assert any("missing execution" in error for error in report["errors"])

    witness = world.witness()
    mismatch = witness.execute(https_call("POST", "example.test", 80, "/join", body="no"), receipt_id)
    assert mismatch.divergence == "mismatch"
    code, report = _verify_join(world.log, world.witness_log, world.witness_pub, call, receipt_id)
    assert code == 1
    assert any(error.startswith("mismatch:") for error in report["errors"])

    denied = world.service.handle({
        "op": "evaluate",
        "proposal": proposal("read", "nope"),
        "call": {"shape": "shell", "cmd": "id"},
    })
    unauthorized = witness.execute(call, denied["receipt"]["receipt_id"])
    assert unauthorized.divergence == "unauthorized"
    code, report = _verify_join(world.log, world.witness_log, world.witness_pub)
    assert any(error.startswith("unauthorized:") for error in report["errors"])

    (tmp_path / "replay").mkdir()
    fresh = World(tmp_path / "replay")
    replay_call = https_call("GET", "example.test", 80, "/replay")
    replay_id = fresh.allow(replay_call)["receipt"]["receipt_id"]
    replay = fresh.witness()
    assert replay.execute(replay_call, replay_id).status == "completed"
    assert replay.execute(replay_call, replay_id).divergence == "reused"
    code, report = _verify_join(fresh.log, fresh.witness_log, fresh.witness_pub, replay_call, replay_id)
    assert any(error.startswith("reused:") for error in report["errors"])
    assert not any("missing execution" in error for error in report["errors"])

    (tmp_path / "late").mkdir()
    late_world = World(tmp_path / "late")
    late_call = https_call("GET", "example.test", 80, "/late")
    late_receipt = late_world.allow(late_call)["receipt"]
    issued = _issued(late_receipt["issued_at"])
    assert late_world.witness(clock=lambda: issued + 3601).execute(late_call, late_receipt["receipt_id"]).divergence == "late"
    code, report = _verify_join(late_world.log, late_world.witness_log, late_world.witness_pub)
    assert any(error.startswith("late:") for error in report["errors"])

    (tmp_path / "good").mkdir()
    good = World(tmp_path / "good")
    good_call = https_call("GET", "example.test", 80, "/good")
    good_id = good.allow(good_call)["receipt"]["receipt_id"]
    assert good.witness().execute(good_call, good_id).status == "completed"
    code, report = _verify_join(good.log, good.witness_log, good.witness_pub, good_call, good_id)
    assert code == 0 and report["ok"] is True, report

    tampered = good.witness_log.read_text(encoding="utf-8").replace("ed25519:", "ed25519:00", 1)
    bad_log = tmp_path / "tampered.jsonl"
    bad_log.write_text(tampered, encoding="utf-8")
    code, report = _verify_join(good.log, bad_log, good.witness_pub)
    assert code == 1
    assert any("signature" in error for error in report["errors"])

    cutoff = tmp_path / "cutoff.pub"
    cutoff.write_text(good.witness_pub.read_text(encoding="utf-8").strip() + f" through {good_id}\n", encoding="utf-8")
    refused = subprocess.run(
        [sys.executable, str(VERIFIER), str(good.log), "--witness-log", str(good.witness_log),
         "--witness-keys", str(cutoff)],
        capture_output=True, text=True,
    )
    assert refused.returncode == 2
    assert "through" in refused.stderr
