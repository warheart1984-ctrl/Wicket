"""The signer service: key, policy and log live in one process, Nova asks over a socket."""

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

if os.name != "posix":
    pytest.skip("the signer service speaks over Unix domain sockets", allow_module_level=True)

from runtime.ick_service import Service, make_server
from runtime.kernel import Kernel, KernelError, find_binary

try:
    BINARY = find_binary()
except KernelError:
    pytest.skip("infinityctl not built (run `cargo build`)", allow_module_level=True)

ROOT = Path(__file__).resolve().parent.parent


def proposal(text="hi", effect="read", risk="low", approval_id=None):
    p = {"version": "infinity.proposal.v1", "proposal_id": f"p-{text}", "actor": {"kind": "agent", "id": "nova"},
         "action": "chat_completion", "target": "t", "effect": effect, "risk": risk,
         "requires_human_approval": False, "policy_version": "policy-test-v1",
         "payload": {"text": text}, "evidence_refs": []}
    if approval_id:
        p["approval_id"] = approval_id
    return p


def make_policy(path, **fields):
    body = {"version": "infinity.policy.v1", "policy_id": "policy-test-v1", "denied_effects": [],
            "effects_requiring_approval": [], **fields}
    path.write_text(json.dumps(body))
    return path


def keygen(directory):
    private, public = directory / "key.priv", directory / "key.pub"
    subprocess.run([BINARY, "keygen", "--out", str(private), "--public-out", str(public)],
                   check=True, capture_output=True)
    return private, public


def ask(path, request, *, raw=None, timeout=15):
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(timeout)
        conn.connect(str(path))
        conn.sendall(raw if raw is not None else json.dumps(request).encode() + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
    return json.loads(data)


class Running:
    def __init__(self, tmp_path, policy_fields=None, approvals=True, **server_kwargs):
        self.dir = tmp_path
        self.private, self.public = keygen(tmp_path)
        self.policy = make_policy(tmp_path / "policy.json", **(policy_fields or {}))
        self.log, self.anchor = tmp_path / "log" / "r.jsonl", tmp_path / "safe" / "a.jsonl"
        self.approvals = tmp_path / "human" / "approvals.jsonl" if approvals else None
        kernel = Kernel(self.policy, self.log, binary=BINARY, anchor=self.anchor, sign_key=self.private)
        self.service = Service(kernel, approvals=self.approvals)
        self.sock = tmp_path / "s.sock"
        self.server = make_server(self.service, self.sock, **server_kwargs)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def call(self, request, **kw):
        return ask(self.sock, request, **kw)

    def evaluate(self, p, ids=()):
        return self.call({"op": "evaluate", "proposal": p, "approval_ids": list(ids)})

    def verify(self):
        checker = Kernel(self.policy, self.log, binary=BINARY, anchor=self.anchor,
                         trusted_keys=self.public, require_signatures=True)
        return checker.verify()

    def approve(self, proposal_hash, approval_id="approval-1", expires_in=600):
        self.approvals.parent.mkdir(parents=True, exist_ok=True)
        with self.approvals.open("a") as handle:
            handle.write(json.dumps({"approval_id": approval_id, "proposal_hash": proposal_hash,
                                     "expires_at": time.time() + expires_in, "uses": 1}) + "\n")


@pytest.fixture
def svc(tmp_path):
    running = Running(tmp_path)
    yield running
    running.server.shutdown()


def test_it_answers_with_its_own_policy_and_signs_into_its_own_log(svc):
    assert svc.call({"op": "info"}) == {"ok": True, "result": {"policy_id": "policy-test-v1"}}
    out = svc.evaluate(proposal())["result"]
    assert out["decision"]["verdict"] == "allow"
    assert out["receipt"]["key_id"] and out["receipt"]["signature"]
    assert svc.verify() is True  # signed, chained, matches the anchor


def test_the_verdict_comes_from_the_services_policy_not_from_the_caller(tmp_path):
    running = Running(tmp_path, policy_fields={"denied_effects": ["write"]})
    try:
        # the caller can claim anything in the proposal, but cannot make the policy allow a write
        denied = running.evaluate(proposal("x", effect="write"))["result"]
        assert denied["decision"]["verdict"] == "deny" and denied["receipt"]["signature"]
        forged = proposal("y", effect="write")
        forged["requires_human_approval"] = False
        forged["payload"]["verdict"] = "allow"  # asking for a verdict is itself refused
        assert running.evaluate(forged)["result"]["decision"]["verdict"] == "deny"
        assert running.verify() is True
    finally:
        running.server.shutdown()


def test_outcomes_are_signed_and_chained_and_only_for_an_open_allow(svc):
    receipt = svc.evaluate(proposal())["result"]["receipt"]["receipt_id"]
    sha = "sha256:" + "a" * 64
    done = svc.call({"op": "record_outcome", "decision_receipt": receipt, "status": "completed",
                     "request_sha256": sha, "response_sha256": sha})
    assert done["ok"] and done["result"]["outcome"]["receipt_id"]
    assert svc.verify() is True
    again = svc.call({"op": "record_outcome", "decision_receipt": receipt, "status": "failed"})
    assert again["ok"] is False  # one outcome per decision
    unknown = svc.call({"op": "record_outcome", "decision_receipt": "sha3-256:nope", "status": "completed"})
    assert unknown["ok"] is False and svc.verify() is True


def test_bad_requests_are_refused_and_write_nothing(svc):
    bad = [
        {"op": "nope"}, [1], {"op": "evaluate"}, {"op": "evaluate", "proposal": "x"},
        {"op": "evaluate", "proposal": proposal(), "approval_ids": "a"},
        {"op": "evaluate", "proposal": proposal(), "approval_ids": [1]},
        {"op": "evaluate", "proposal": proposal(), "approval_ids": ["a"] * 9},
        {"op": "record_outcome", "decision_receipt": "x y", "status": "completed"},
        {"op": "record_outcome", "decision_receipt": "abc", "status": "weird"},
        {"op": "record_outcome", "decision_receipt": "abc", "status": "completed", "request_sha256": "nope"},
        {"op": "record_outcome", "decision_receipt": "abc", "status": "completed", "response_sha256": 5},
    ]
    for request in bad:
        reply = svc.call(request)
        assert reply["ok"] is False and not reply["error"].startswith("kernel:"), request  # refused up front
    assert svc.call(None, raw=b"not json\n")["error"] == "request is not JSON"
    big = svc.call(None, raw=b'{"op":"evaluate","pad":"' + b"x" * (1 << 20) + b'"}\n')
    assert big["error"] == "request too large"
    assert not svc.log.exists()
    assert svc.call({"op": "info"})["ok"] is True  # and it is still serving


def test_a_made_up_approval_is_refused_and_a_real_one_is_bound_to_its_request(svc):
    p = proposal("needs")
    svc.service.kernel.policy.write_text(json.dumps({
        "version": "infinity.policy.v1", "policy_id": "policy-test-v1", "denied_effects": [],
        "effects_requiring_approval": ["read"]}))
    first = svc.evaluate(p)["result"]
    assert first["decision"]["verdict"] == "await_human_approval"
    h = first["decision"]["proposal_hash"]
    assert svc.service.kernel.proposal_hash(p) == h
    assert svc.service.kernel.proposal_hash({**p, "approval_id": "approval-1"}) == h  # id is not part of it

    assert svc.evaluate({**p, "approval_id": "approval-made-up"}, ["approval-made-up"])["ok"] is False
    svc.approve(h)
    other = proposal("other")
    assert svc.evaluate({**other, "approval_id": "approval-1"}, ["approval-1"])["ok"] is False  # other request
    ok = svc.evaluate({**p, "approval_id": "approval-1"}, ["approval-1"])["result"]
    assert ok["decision"]["verdict"] == "allow"
    assert svc.verify() is True


def test_expired_or_denied_approvals_and_a_missing_file_are_refused(tmp_path):
    running = Running(tmp_path, policy_fields={"effects_requiring_approval": ["read"]})
    try:
        p = proposal()
        h = running.evaluate(p)["result"]["decision"]["proposal_hash"]
        running.approve(h, "approval-old", expires_in=-5)
        assert running.evaluate({**p, "approval_id": "approval-old"}, ["approval-old"])["ok"] is False
        running.approve(h, "approval-good")
        Path(str(running.approvals) + ".denials").write_text(json.dumps({"proposal_hash": h}) + "\n")
        assert running.evaluate({**p, "approval_id": "approval-good"}, ["approval-good"])["ok"] is False
        Path(str(running.approvals) + ".denials").unlink()
        Path(str(running.approvals) + ".denials").mkdir()  # unreadable as a file: fail closed
        assert running.evaluate({**p, "approval_id": "approval-good"}, ["approval-good"])["ok"] is False
    finally:
        running.server.shutdown()
    bare = Running(tmp_path / "bare", approvals=False) if (tmp_path / "bare").mkdir() is None else None
    try:
        assert bare.evaluate(proposal(), ["approval-1"])["ok"] is False  # no approvals file at all
    finally:
        bare.server.shutdown()


def test_the_socket_is_not_open_to_everyone_and_stale_files_are_handled(tmp_path):
    running = Running(tmp_path, mode=0o600)
    try:
        assert (running.sock.stat().st_mode & 0o777) == 0o600
        with pytest.raises(OSError, match="already listening"):
            make_server(running.service, running.sock)
    finally:
        running.server.shutdown()
        running.server.server_close()
    running.sock.touch()  # a leftover file nobody is listening on
    again = make_server(running.service, running.sock)
    again.server_close()


def test_service_refuses_to_start_without_a_usable_key_or_policy(tmp_path):
    base = [sys.executable, "-m", "runtime.ick_service", "serve", "--socket", str(tmp_path / "s"),
            "--log", str(tmp_path / "l.jsonl")]
    policy = make_policy(tmp_path / "p.json")
    cases = [
        base + ["--policy", str(tmp_path / "missing.json"), "--sign-key", str(tmp_path / "k")],
        base + ["--policy", str(policy), "--sign-key", str(tmp_path / "missing.key"), "--socket-mode", "zz"],
    ]
    for cmd in cases:
        done = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=30)
        assert done.returncode == 2, (cmd, done.stderr)


def test_a_key_others_can_read_stops_the_service_answering(tmp_path):
    running = Running(tmp_path)
    try:
        os.chmod(running.private, 0o644)
        reply = running.evaluate(proposal())
        assert reply["ok"] is False and "key" in reply["error"].lower()
        assert not running.log.exists()
    finally:
        running.server.shutdown()


# --- the real thing: separate accounts ----------------------------------------------------------

SERVICE_UID, NOVA_UID, OTHER_UID = 64011, 64012, 64013

CLIENT = r'''
import json, socket, sys
path = sys.argv[1]
out = {}
for name in ("key", "log_write", "policy_write"):
    target = {"key": sys.argv[2], "log_write": sys.argv[3], "policy_write": sys.argv[4]}[name]
    try:
        open(target, "a" if name != "key" else "r").close()
        out[name] = "allowed"
    except PermissionError:
        out[name] = "denied"
with socket.socket(socket.AF_UNIX) as c:
    c.settimeout(20)
    c.connect(path)
    c.sendall(json.dumps(json.loads(sys.argv[5])).encode() + b"\n")
    data = b""
    while not data.endswith(b"\n"):
        chunk = c.recv(65536)
        if not chunk: break
        data += chunk
out["reply"] = json.loads(data)
print(json.dumps(out))
'''


def as_uid(uid):
    def drop():
        os.setgid(uid)
        os.setuid(uid)
    return drop


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="needs root to run as other accounts")
def test_nova_on_another_account_can_get_receipts_signed_but_cannot_touch_key_policy_or_log(tmp_path):
    root = tmp_path / "w"
    root.mkdir()
    for parent in (tmp_path.parent.parent, tmp_path.parent, tmp_path):  # let other accounts walk down to the test files
        os.chmod(parent, 0o755)
    os.chmod(root, 0o755)
    (root / "run").mkdir()
    os.chown(root / "run", SERVICE_UID, SERVICE_UID)
    private, public = keygen(root)
    policy = make_policy(root / "policy.json")
    (root / "log").mkdir()
    (root / "safe").mkdir()
    log, anchor, sock = root / "log" / "r.jsonl", root / "safe" / "a.jsonl", root / "run" / "s.sock"
    for path in (private, policy, root / "log", root / "safe"):
        os.chown(path, SERVICE_UID, SERVICE_UID)
    os.chmod(private, 0o600)
    os.chmod(root / "log", 0o755)  # Nova may read the log, not write it
    os.chmod(policy, 0o644)
    os.chmod(root / "safe", 0o700)  # the anchor is not even readable by Nova
    os.chmod(public, 0o644)
    service = subprocess.Popen(
        [sys.executable, "-m", "runtime.ick_service", "serve", "--socket", str(sock), "--policy", str(policy),
         "--log", str(log), "--anchor", str(anchor), "--sign-key", str(private), "--binary", BINARY,
         "--socket-mode", "666", "--allow-uid", str(NOVA_UID)],
        cwd=ROOT, preexec_fn=as_uid(SERVICE_UID), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    try:
        for _ in range(100):
            if sock.exists():
                break
            time.sleep(0.1)
        assert sock.exists(), (service.poll(), service.stderr.read() if service.poll() is not None else '')

        def client(uid, request):
            done = subprocess.run(
                [sys.executable, "-c", CLIENT, str(sock), str(private), str(log), str(policy), json.dumps(request)],
                preexec_fn=as_uid(uid), capture_output=True, text=True, timeout=60)
            assert done.returncode == 0, done.stderr
            return json.loads(done.stdout)

        nova = client(NOVA_UID, {"op": "evaluate", "proposal": proposal(), "approval_ids": []})
        assert nova["key"] == "denied" and nova["log_write"] == "denied" and nova["policy_write"] == "denied"
        assert nova["reply"]["ok"] and nova["reply"]["result"]["receipt"]["signature"]

        stranger = client(OTHER_UID, {"op": "info"})  # not on the allow list
        assert stranger["reply"]["ok"] is False and "may not use" in stranger["reply"]["error"]

        checker = Kernel(policy, log, binary=BINARY, trusted_keys=public, require_signatures=True)
        assert checker.verify() is True  # signed by a key Nova never saw
        assert len(log.read_text().splitlines()) == 1
    finally:
        service.terminate()
        service.wait(timeout=10)
    assert not sock.exists()  # cleaned up on exit
