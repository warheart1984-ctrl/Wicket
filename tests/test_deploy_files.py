"""The deployment files must match the code they start, and the audit must catch a wrong setup."""

import argparse
import configparser
import importlib.util
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
UNITS = DEPLOY / "systemd"


def load_check_setup():
    spec = importlib.util.spec_from_file_location("check_setup", DEPLOY / "check_setup.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_setup"] = module
    spec.loader.exec_module(module)  # needs pwd/grp: Unix only
    return module


def read_unit(name):
    parser = configparser.RawConfigParser(strict=False)
    parser.optionxform = str
    text = (UNITS / name).read_text(encoding="utf-8")
    text = re.sub(r"\\\n\s*", " ", text)  # join continued lines
    parser.read_string(text)
    return parser


def setting(unit, key, section="Service"):
    """All values of a (possibly repeated) setting; configparser keeps only one, so read the lines."""
    text = re.sub(r"\\\n\s*", " ", (UNITS / unit).read_text(encoding="utf-8"))
    inside, out = None, []
    for line in text.splitlines():
        m = re.match(r"\[(\w+)\]", line.strip())
        if m:
            inside = m.group(1)
        elif inside == section and line.startswith(key + "="):
            out.append(line.split("=", 1)[1].strip())
    return out


# --- every file is there and says what the README says ------------------------------------------------

def test_the_expected_files_exist_and_the_scripts_are_executable_text():
    for name in ("ick-signer.service", "ick-anchor-watch.service", "nova-api.service",
                 "sysusers.d/infinity-core.conf", "tmpfiles.d/infinity-core.conf"):
        assert (UNITS / name).is_file(), name
    for name in ("etc/ick-anchor-watch.env.example", "etc/nova.env.example", "cron/ick-anchor-publish",
                 "run-operator.sh", "check_setup.py", "README.md"):
        assert (DEPLOY / name).is_file(), name
    if os.name == "posix":
        assert os.access(DEPLOY / "run-operator.sh", os.X_OK)


@pytest.mark.parametrize("unit", ["ick-signer.service", "ick-anchor-watch.service", "nova-api.service"])
def test_every_unit_is_sandboxed_and_runs_as_its_own_account(unit):
    for directive in ("NoNewPrivileges=yes", "ProtectSystem=strict", "PrivateTmp=yes", "ProtectHome=yes",
                      "RestrictSUIDSGID=yes", "LockPersonality=yes", "CapabilityBoundingSet="):
        assert directive.split("=")[0] in {l.split("=")[0] for l in (UNITS / unit).read_text().splitlines()}, directive
    assert setting(unit, "NoNewPrivileges") == ["yes"] and setting(unit, "ProtectSystem") == ["strict"]
    users = setting(unit, "User")
    assert len(users) == 1 and users[0] not in ("root", "nobody")
    assert setting(unit, "CapabilityBoundingSet") == [""]  # no capabilities at all
    assert "ReadWritePaths" in {l.split("=")[0] for l in (UNITS / unit).read_text().splitlines()}


def test_the_three_roles_are_three_different_accounts():
    users = [setting(u, "User")[0] for u in ("ick-signer.service", "ick-anchor-watch.service", "nova-api.service")]
    assert len(set(users)) == 3 and users == ["ick-signer", "ick-publisher", "nova"]


def test_the_signer_has_no_network_and_nova_cannot_write_what_the_signer_owns():
    signer = "ick-signer.service"
    assert setting(signer, "IPAddressDeny") == ["any"] and setting(signer, "RestrictAddressFamilies") == ["AF_UNIX"]
    assert setting(signer, "ReadWritePaths") == ["/var/lib/ick"]
    assert setting("nova-api.service", "ReadWritePaths") == ["/var/lib/nova"]
    assert setting("ick-anchor-watch.service", "ReadWritePaths") == ["/var/lib/ick-publisher"]
    # the publisher may read the log and anchor through a group, and is not in the socket group
    assert setting("ick-anchor-watch.service", "SupplementaryGroups") == ["ick-audit"]
    assert setting("nova-api.service", "SupplementaryGroups") == ["ick-socket"]
    assert setting(signer, "Group") == ["ick-socket"]


def test_sysusers_and_tmpfiles_match_the_units():
    sysusers = (UNITS / "sysusers.d/infinity-core.conf").read_text()
    for name in ("ick-socket", "ick-audit", "ick-signer", "ick-publisher", "nova"):
        assert re.search(rf"^[gu]\s+{re.escape(name)}\s", sysusers, re.M), name
    assert re.search(r"^m\s+nova\s+ick-socket", sysusers, re.M)
    assert re.search(r"^m\s+ick-publisher\s+ick-audit", sysusers, re.M)
    assert not re.search(r"^m\s+nova\s+ick-audit", sysusers, re.M)  # Nova never reads the log or the anchor
    assert not re.search(r"^m\s+ick-publisher\s+ick-socket", sysusers, re.M)  # the publisher never asks the signer
    tmpfiles = {m.group(2): m.groups() for m in re.finditer(r"^d\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", (UNITS / "tmpfiles.d/infinity-core.conf").read_text(), re.M)}
    by_path = {m.group(1): (m.group(2), m.group(3), m.group(4)) for m in re.finditer(
        r"^d\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", (UNITS / "tmpfiles.d/infinity-core.conf").read_text(), re.M)}
    assert by_path["/var/lib/ick/log"] == ("2750", "ick-signer", "ick-audit")
    assert by_path["/var/lib/ick/anchor"] == ("2750", "ick-signer", "ick-audit")
    assert by_path["/etc/ick/human"][1] == "root"  # handed to the operator by hand
    # every path a unit reads or writes is in a directory that tmpfiles creates
    for unit in ("ick-signer.service", "ick-anchor-watch.service", "nova-api.service"):
        for path in setting(unit, "ReadWritePaths"):
            assert path in by_path, (unit, path)
    del tmpfiles


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze is not installed")
@pytest.mark.parametrize("unit", ["ick-signer.service", "ick-anchor-watch.service", "nova-api.service"])
def test_systemd_accepts_the_units_and_rates_their_exposure_low(unit):
    verify = subprocess.run(["systemd-analyze", "verify", str(UNITS / unit)], capture_output=True, text=True)
    problems = [l for l in verify.stderr.splitlines()
                if l.strip() and "is not executable" not in l and "Failed to load" not in l
                and "No such file" not in l and "Special user" not in l]
    assert not problems, problems  # only the programs and accounts that exist on a real server are missing
    security = subprocess.run(["systemd-analyze", "security", "--offline=true", str(UNITS / unit)],
                              capture_output=True, text=True)
    score = re.search(r"exposure level for \S+: ([\d.]+) (\w+)", security.stdout)
    if score is None:
        pytest.skip("this systemd cannot rate units offline")
    assert float(score.group(1)) <= 2.5, security.stdout[-400:]


# --- the commands in the units really are what the programs accept -------------------------------------

def exec_args(unit, name="ExecStart"):
    (line,) = setting(unit, name)
    return shlex.split(line)


def fill(arg, mapping):
    for old, new in mapping.items():
        arg = arg.replace(old, new)
    return arg


posix_only = pytest.mark.skipif(os.name != "posix", reason="Unix sockets and accounts")


@posix_only
def test_the_signer_unit_command_starts_the_real_service(tmp_path):
    from runtime.kernel import KernelError, find_binary

    try:
        binary = find_binary()
    except KernelError:
        pytest.skip("infinityctl not built")
    key, pub = tmp_path / "signing.priv", tmp_path / "trusted-keys.pub"
    subprocess.run([binary, "keygen", "--out", str(key), "--public-out", str(pub)], check=True, capture_output=True)
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-demo-v1"}))
    (tmp_path / "human").mkdir()
    mapping = {"/run/ick/ick.sock": str(tmp_path / "ick.sock"), "/etc/ick/policy.json": str(policy),
               "/var/lib/ick/log/receipts.jsonl": str(tmp_path / "log" / "receipts.jsonl"),
               "/var/lib/ick/anchor/anchor.jsonl": str(tmp_path / "anchor" / "anchor.jsonl"),
               "/etc/ick/signing.priv": str(key), "/etc/ick/human/approvals.jsonl": str(tmp_path / "human" / "a.jsonl"),
               "/opt/infinity-core/target/release/infinityctl": binary}
    command = [fill(a, mapping) for a in exec_args("ick-signer.service")]
    command[0] = sys.executable
    (tmp_path / "log").mkdir()
    (tmp_path / "anchor").mkdir()
    proc = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(100):
            if (tmp_path / "ick.sock").exists() or proc.poll() is not None:
                break
            time.sleep(0.1)
        assert proc.poll() is None, proc.stderr.read()
        assert oct((tmp_path / "ick.sock").stat().st_mode & 0o777) == "0o660"
        with socket.socket(socket.AF_UNIX) as c:
            c.settimeout(10)
            c.connect(str(tmp_path / "ick.sock"))
            c.sendall(b'{"op":"info"}\n')
            assert json.loads(c.recv(4096))["result"]["policy_id"] == "policy-demo-v1"
    finally:
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=15) == 0  # a clean stop, as the unit's KillSignal expects
    assert not (tmp_path / "ick.sock").exists()


@posix_only
def test_the_publisher_unit_command_runs_one_real_publish(tmp_path):
    from runtime.kernel import Kernel, KernelError, find_binary

    try:
        binary = find_binary()
    except KernelError:
        pytest.skip("infinityctl not built")
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    key, pub = tmp_path / "k.priv", tmp_path / "k.pub"
    subprocess.run([binary, "keygen", "--out", str(key), "--public-out", str(pub)], check=True, capture_output=True)
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-demo-v1"}))
    log, anchor = tmp_path / "log.jsonl", tmp_path / "anchor.jsonl"
    from runtime.chat import run_turn

    class Client:
        def __call__(self, url, payload, headers):
            return {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}

    os.environ["GROQ_API_KEY"] = "k"
    try:
        run_turn("hi", "groq", Kernel(policy, log, binary=binary, anchor=anchor, sign_key=key), client=Client())
    finally:
        del os.environ["GROQ_API_KEY"]
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
    status = tmp_path / "status.json"
    mapping = {"${ANCHOR_REPO}": str(remote), "${ANCHOR_INTERVAL}": "300", "/var/lib/ick/anchor/anchor.jsonl": str(anchor),
               "/var/lib/ick/log/receipts.jsonl": str(log), "/etc/ick/trusted-keys.pub": str(pub),
               "/var/lib/ick-publisher/status.json": str(status)}
    command = [fill(a, mapping) for a in exec_args("ick-anchor-watch.service")] + ["--max-runs", "1"]
    command[0] = sys.executable
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t"}
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60, env=env)
    assert done.returncode == 0, done.stderr
    report = json.loads(status.read_text())
    assert report["consecutive_failures"] == 0 and report["published_records"] >= 1


def test_the_cron_line_uses_flags_the_publisher_accepts():
    line = next(l for l in (DEPLOY / "cron/ick-anchor-publish").read_text().splitlines() if l.startswith("*/5"))
    command = shlex.split(line.split("ick-publisher", 1)[1].split(">/dev/null")[0])
    assert "publish" in command and "--status-file" in command and "--require-signatures" in command
    sys.path.insert(0, str(ROOT))
    from runtime import anchor_git

    parser_flags = set(re.findall(r"--[a-z-]+", (ROOT / "runtime/anchor_git.py").read_text()))
    assert {a for a in command if a.startswith("--")} <= parser_flags


def test_nova_unit_settings_are_accepted_by_nova_and_the_forbidden_ones_are_absent():
    sys.path.insert(0, str(ROOT / "nova-shell"))
    from nova.ick import IckGate

    env = {}
    for line in setting("nova-api.service", "Environment"):
        k, _, v = line.partition("=")
        env[k] = v
    assert env["NOVA_ICK_SERVICE"] == "/run/ick/ick.sock"
    for forbidden in ("NOVA_ICK_POLICY", "NOVA_ICK_SIGN_KEY", "NOVA_ICK_BIN", "NOVA_ICK_LOG"):
        assert forbidden not in env
    gate = IckGate.from_env({**env, "NOVA_ICK_STATE": "/tmp/x"})
    assert gate is not None and gate.service == Path("/run/ick/ick.sock")  # a Path, so Windows spells it differently
    for forbidden in ("NOVA_ICK_POLICY", "NOVA_ICK_SIGN_KEY", "NOVA_ICK_BIN"):
        assert forbidden not in (DEPLOY / "etc/nova.env.example").read_text().replace("Do NOT put", "").split("NOVA_PROVIDER")[1]
    assert setting("nova-api.service", "ExecStart") == ["/opt/infinity-core/venv/bin/python -m nova.api"]


def test_the_operator_script_passes_flags_the_operator_screen_accepts():
    text = (DEPLOY / "run-operator.sh").read_text()
    flags = set(re.findall(r"^\s+(--[a-z-]+)", text, re.M))
    source = (ROOT / "nova-shell/nova/operator_ui.py").read_text()
    for flag in flags:
        assert f'"{flag}"' in source, flag
    assert "--require-signatures" in text and "set -eu" in text


# --- the audit ----------------------------------------------------------------------------------------

@posix_only
def test_the_permission_rule_matches_unix_for_owner_group_other_and_root():
    cs = load_check_setup()
    me = cs.Account("me", 1000, frozenset({1000, 50}))
    stranger = cs.Account("x", 2000, frozenset({2000}))
    root = cs.Account("root", 0, frozenset({0}))
    assert cs.mode_allows(me, 0o640, 1000, 1, 6) and not cs.mode_allows(me, 0o440, 1000, 1, 2)
    assert cs.mode_allows(me, 0o040, 1, 50, 4) and not cs.mode_allows(me, 0o040, 1, 50, 2)
    assert not cs.mode_allows(stranger, 0o640, 1, 1, 4) and cs.mode_allows(stranger, 0o644, 1, 1, 4)
    assert cs.mode_allows(me, 0o070, 1000, 50, 4) is False  # the owner's bits win even if worse than the group's
    assert cs.mode_allows(root, 0, 1, 1, 7)


UIDS = {"signer": 64011, "nova": 64012, "publisher": 64013, "operator": 64014}
G_SOCKET, G_AUDIT = 64020, 64021


def rig(tmp_path):
    """The file layout from deploy/README.md, with real owners (needs root to chown)."""
    cs = load_check_setup()
    accounts = {
        "ick-signer": cs.Account("ick-signer", UIDS["signer"], frozenset({UIDS["signer"], G_SOCKET})),
        "nova": cs.Account("nova", UIDS["nova"], frozenset({UIDS["nova"], G_SOCKET})),
        "ick-publisher": cs.Account("ick-publisher", UIDS["publisher"], frozenset({UIDS["publisher"], G_AUDIT})),
        "alice": cs.Account("alice", UIDS["operator"], frozenset({UIDS["operator"], G_AUDIT})),
    }
    paths = {}

    def make(rel, mode, uid, gid, directory=False):
        path = tmp_path / rel
        if directory:
            path.mkdir(parents=True, exist_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x")
        os.chown(path, uid, gid)
        os.chmod(path, mode)
        return str(path)

    for parent in (tmp_path.parent.parent, tmp_path.parent, tmp_path):
        os.chmod(parent, 0o755)
    S, N, P, O = UIDS["signer"], UIDS["nova"], UIDS["publisher"], UIDS["operator"]
    make("etc/ick", 0o755, 0, 0, True)
    make("etc/ick/human", 0o755, O, O, True)
    paths["key"] = make("etc/ick/signing.priv", 0o600, S, S)
    paths["policy"] = make("etc/ick/policy.json", 0o644, 0, 0)
    paths["trusted_keys"] = make("etc/ick/trusted-keys.pub", 0o644, 0, 0)
    paths["approvals"] = make("etc/ick/human/approvals.jsonl", 0o644, O, O)
    make("etc/ick/human/approvals.jsonl.denials", 0o644, O, O)
    make("var/lib/ick", 0o750, S, G_AUDIT, True)
    make("var/lib/ick/log", 0o2750, S, G_AUDIT, True)
    make("var/lib/ick/anchor", 0o2750, S, G_AUDIT, True)
    paths["log"] = make("var/lib/ick/log/receipts.jsonl", 0o640, S, G_AUDIT)
    paths["anchor"] = make("var/lib/ick/anchor/anchor.jsonl", 0o640, S, G_AUDIT)
    make("run/ick", 0o750, S, G_SOCKET, True)
    sock = tmp_path / "run/ick/ick.sock"
    s = socket.socket(socket.AF_UNIX)
    s.bind(str(sock))
    os.chown(sock, S, G_SOCKET)
    os.chmod(sock, 0o660)
    paths["socket"] = str(sock)
    make("etc/ick-publisher", 0o750, P, P, True)
    paths["deploy_key"] = make("etc/ick-publisher/deploy_key", 0o600, P, P)
    make("etc/nova", 0o750, 0, UIDS["nova"], True)
    paths["nova_env"] = make("etc/nova/nova.env", 0o640, 0, UIDS["nova"])
    Path(paths["nova_env"]).write_text("NOVA_PROVIDER=external\nNOVA_EXTERNAL_API_KEY=k\n# NOVA_ICK_POLICY=ignored comment\n")
    args = argparse.Namespace(
        signer="ick-signer", nova="nova", publisher="ick-publisher", operator="alice", key=paths["key"],
        policy=paths["policy"], trusted_keys=paths["trusted_keys"], log=paths["log"], anchor=paths["anchor"],
        approvals=paths["approvals"], denials=paths["approvals"] + ".denials", socket=paths["socket"],
        deploy_key=paths["deploy_key"], nova_env=paths["nova_env"])
    return cs, args, accounts, paths, s


def run_audit(cs, args, accounts):
    report = cs.audit(args, resolve=lambda name: accounts.get(name))
    fails = [r.what for r in report.results if r.status == "FAIL"]
    passes = [r for r in report.results if r.status == "PASS"]
    return fails, passes, report


def open_path(path, upto):
    """Make every directory from `path` up to `upto` searchable by everyone (a sloppy chmod -R)."""
    path = Path(path)
    while path != Path(upto).parent:
        if path.is_dir():
            os.chmod(path, os.stat(path).st_mode | 0o755 | (0o2000 if os.stat(path).st_mode & 0o2000 else 0))
        path = path.parent


root_only = pytest.mark.skipif(os.name != "posix" or (hasattr(os, "geteuid") and os.geteuid() != 0),
                               reason="needs root to give files to other accounts")


@root_only
def test_the_layout_in_the_readme_passes_the_audit(tmp_path):
    cs, args, accounts, paths, sock = rig(tmp_path)
    try:
        fails, passes, report = run_audit(cs, args, accounts)
        assert fails == [], fails
        assert len(passes) >= 30  # the audit checked a lot, not nothing
        assert not [r for r in report.results if r.status == "SKIP"]
    finally:
        sock.close()


@root_only
@pytest.mark.parametrize("what, damage, expected", [
    ("the key is group-readable by Nova's group", lambda p, a: (os.chown(p["key"], UIDS["signer"], G_SOCKET), os.chmod(p["key"], 0o640)), "nova cannot read the signing key"),
    ("the key is world-readable", lambda p, a: os.chmod(p["key"], 0o644), "the signing key is mode 0600 or tighter"),
    ("the key belongs to Nova", lambda p, a: os.chown(p["key"], UIDS["nova"], UIDS["nova"]), "the signing key is owned by the signer"),
    ("Nova owns the policy", lambda p, a: os.chown(p["policy"], UIDS["nova"], UIDS["nova"]), "nova cannot write the policy"),
    ("the policy directory is writable by everyone", lambda p, a: os.chmod(os.path.dirname(p["policy"]), 0o777), "nova cannot replace files in"),
    ("Nova can write the log", lambda p, a: (os.chown(p["log"], UIDS["signer"], G_SOCKET), os.chmod(p["log"], 0o660), open_path(p["log"], Path(p["log"]).parents[2])), "nova cannot write the receipt log"),
    ("the log directory is writable by Nova's group", lambda p, a: (os.chown(os.path.dirname(p["log"]), UIDS["signer"], G_SOCKET), os.chmod(os.path.dirname(p["log"]), 0o770), open_path(os.path.dirname(p["log"]), Path(p["log"]).parents[2])), "nova cannot create or replace files next to the receipt log"),
    ("Nova's group may write the log directory but the directory above is closed to it: reachable by no one", lambda p, a: (os.chown(os.path.dirname(p["log"]), UIDS["signer"], G_SOCKET), os.chmod(os.path.dirname(p["log"]), 0o2775)), None),
    ("Nova could write the log but its directory is closed: not a mistake, the path is protected", lambda p, a: os.chmod(p["log"], 0o646), None),
    ("the publisher can write the anchor", lambda p, a: os.chmod(p["anchor"], 0o660), "ick-publisher cannot write the anchor"),
    ("Nova can read the anchor", lambda p, a: (os.chown(p["anchor"], UIDS["signer"], G_SOCKET), os.chmod(p["anchor"], 0o640), open_path(p["anchor"], Path(p["anchor"]).parents[2])), "nova cannot read the anchor"),
    ("the publisher cannot read the anchor", lambda p, a: os.chmod(p["anchor"], 0o600), "the publisher can read the anchor"),
    ("Nova can write the approvals file", lambda p, a: os.chown(p["approvals"], UIDS["nova"], UIDS["nova"]), "nova cannot write the approvals file"),
    ("the approvals directory is writable by Nova", lambda p, a: os.chmod(os.path.dirname(p["approvals"]), 0o777), "nova cannot create files in"),
    ("the denials file is writable by the signer", lambda p, a: (os.chown(p["approvals"] + ".denials", UIDS["signer"], UIDS["signer"])), "ick-signer cannot write the denials file"),
    ("the socket is open to everyone", lambda p, a: (os.chmod(p["socket"], 0o666), open_path(p["socket"], Path(p["socket"]).parents[2])), "ick-publisher cannot write to the signer's socket"),
    ("Nova cannot reach the socket", lambda p, a: os.chmod(p["socket"], 0o600), "Nova can reach the signer's socket"),
    ("the deploy key is readable by Nova", lambda p, a: (os.chown(p["deploy_key"], UIDS["publisher"], G_SOCKET), os.chmod(p["deploy_key"], 0o640), open_path(p["deploy_key"], Path(p["deploy_key"]).parents[1])), "nova cannot read the publisher's deploy key"),
    ("Nova's environment sets the signing key", lambda p, a: Path(p["nova_env"]).write_text("NOVA_ICK_SIGN_KEY=/etc/x\n"), "Nova's environment file names no policy, key or kernel"),
    ("Nova and the publisher share an account", lambda p, a: setattr(a, "publisher", "nova"), "three different accounts"),
    ("the operator cannot read the log", lambda p, a: os.chmod(p["log"], 0o600), "the operator can read the log"),
])
def test_each_wrong_setup_is_reported(tmp_path, what, damage, expected):
    cs, args, accounts, paths, sock = rig(tmp_path)
    try:
        damage(paths, args)
        fails, _, _ = run_audit(cs, args, accounts)
        if expected is None:  # a file left loose but behind a closed directory is not reachable: no finding
            assert fails == [], fails
        else:
            assert any(expected in f for f in fails), (what, fails)
    finally:
        sock.close()


@posix_only
def test_the_audit_reports_missing_files_as_skipped_never_as_passed(tmp_path):
    cs = load_check_setup()
    args = argparse.Namespace(
        signer="a", nova="b", publisher="c", operator=None, key=str(tmp_path / "k"), policy=str(tmp_path / "p"),
        trusted_keys=str(tmp_path / "t"), log=str(tmp_path / "l"), anchor=str(tmp_path / "an"),
        approvals=str(tmp_path / "ap"), denials=str(tmp_path / "ap.denials"), socket=str(tmp_path / "s"),
        deploy_key=str(tmp_path / "d"), nova_env=None)
    accounts = {n: cs.Account(n, 70000 + i, frozenset({70000 + i})) for i, n in enumerate("abc")}
    report = cs.audit(args, resolve=lambda name: accounts.get(name))
    # (a directory that exists can be judged even when the file in it does not, so those are not skips)
    statuses = {r.status for r in report.results
                if "different accounts" not in r.what and "files in" not in r.what and "files next to" not in r.what
                and "create or replace" not in r.what}
    assert statuses == {"SKIP"}


@posix_only
def test_the_audit_command_exits_nonzero_when_a_user_is_missing():
    done = subprocess.run([sys.executable, str(DEPLOY / "check_setup.py"), "--signer", "no-such-user-xyz",
                           "--nova", "no-such-user-abc", "--publisher", "no-such-user-def"],
                          capture_output=True, text=True)
    assert done.returncode == 1 and "FAIL" in done.stdout


# --- the smoke-test script (its dangerous modes are never run by the tests) -----------------------------

SMOKE = DEPLOY / "smoke-test.sh"
bash_only = pytest.mark.skipif(os.name != "posix" or shutil.which("bash") is None, reason="needs bash")


@bash_only
def test_the_smoke_test_script_is_valid_bash_and_defaults_to_a_dry_run():
    assert subprocess.run(["bash", "-n", str(SMOKE)], capture_output=True).returncode == 0
    env = {k: v for k, v in os.environ.items() if k != "SUDO_USER"}
    done = subprocess.run(["bash", str(SMOKE)], capture_output=True, text=True, env=env)
    assert done.returncode == 0 and "Nothing has been changed" in done.stdout
    for step in ("systemd-sysusers", "LOCAL bare git repository", "ickverify.py", "check_setup.py", "probe the separation"):
        assert step in done.stdout, step
    bad = subprocess.run(["bash", str(SMOKE), "--nonsense"], capture_output=True, text=True)
    assert bad.returncode == 2 and "unknown option" in bad.stderr


@bash_only
def test_apply_stops_before_changing_anything_when_it_cannot_be_safe(tmp_path):
    """Run as a plain login with no sudo context: every route out must be a refusal, not a change."""
    env = {k: v for k, v in os.environ.items() if k != "SUDO_USER"}
    done = subprocess.run(["bash", str(SMOKE), "--apply"], capture_output=True, text=True, env=env)
    assert done.returncode == 2 and done.stdout == "", done.stdout
    assert "run this with sudo" in done.stderr or "own login" in done.stderr


def test_the_smoke_test_cleanup_only_removes_what_its_marker_vouches_for():
    text = SMOKE.read_text(encoding="utf-8")
    cleanup = text[text.index("cleanup() {"):text.index('case "$MODE" in')]
    guard = cleanup.index('if [ ! -f "$MARKER" ]')
    assert guard < cleanup.index("rm -rf") and guard < cleanup.index("userdel") and guard < cleanup.index("systemctl stop")
    assert "die " in cleanup[guard:cleanup.index("say \"Removing")]
    assert 'printf \'created by deploy/smoke-test.sh' in text  # the marker the guard looks for is written
    assert text.index("preflight()") < text.index("install_files()") and "preflight\n  say" in text
    assert "rm -rf /etc/ick /etc/ick-publisher /etc/nova /var/lib/ick /var/lib/ick-publisher /var/lib/nova /run/ick" in cleanup
    assert "rm -rf /\n" not in text and "rm -rf $" not in text.replace("rm -rf /etc", "")


@posix_only
def test_the_published_anchor_is_on_the_anchors_branch_even_when_the_repository_defaults_elsewhere(tmp_path):
    """The first real run of the smoke test failed here: a plain clone of the bare repository (whose HEAD
    named a branch the publisher never pushes to) checked out nothing, and the check silently found no file."""
    from runtime.chat import run_turn
    from runtime.kernel import Kernel, KernelError, find_binary
    import runtime.anchor_git as anchor_git

    try:
        binary = find_binary()
    except KernelError:
        pytest.skip("infinityctl not built")
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    key, pub = tmp_path / "k", tmp_path / "k.pub"
    subprocess.run([binary, "keygen", "--out", str(key), "--public-out", str(pub)], check=True, capture_output=True)
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-demo-v1"}))
    log, anchor = tmp_path / "l.jsonl", tmp_path / "a.jsonl"

    class Client:
        def __call__(self, url, payload, headers):
            return {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}

    os.environ["GROQ_API_KEY"] = "k"
    try:
        run_turn("hi", "groq", Kernel(policy, log, binary=binary, anchor=anchor, sign_key=key), client=Client())
    finally:
        del os.environ["GROQ_API_KEY"]
    remote = tmp_path / "r.git"
    subprocess.run(["git", "-c", "init.defaultBranch=master", "init", "--bare", "-q", str(remote)], check=True)
    anchor_git.publish(anchor, str(remote), log=log)
    clone = subprocess.run(["git", "clone", "-q", str(remote), str(tmp_path / "c")], capture_output=True, text=True)
    assert not (tmp_path / "c" / "anchor.jsonl").exists()  # the trap: a plain clone looks empty
    shown = subprocess.run(["git", f"--git-dir={remote}", "show", "anchors:anchor.jsonl"], capture_output=True, text=True)
    assert shown.returncode == 0 and shown.stdout.strip()
    del clone


def test_the_smoke_test_reads_the_published_anchor_from_the_anchors_branch():
    text = SMOKE.read_text(encoding="utf-8")
    assert "show anchors:anchor.jsonl" in text
    assert "symbolic-ref HEAD refs/heads/anchors" in text
    assert "git clone" not in text.split("verify_published()")[1].split("probes()")[0]  # not the trap


# --- the key-switch helpers in the smoke test, run on real files without any services -------------------

@bash_only
def test_the_smoke_test_key_switch_helpers_do_what_the_live_run_relies_on(tmp_path):
    from runtime.chat import run_turn
    from runtime.kernel import Kernel, KernelError, find_binary

    try:
        binary = find_binary()
    except KernelError:
        pytest.skip("infinityctl not built")
    (tmp_path / "log").mkdir()
    log, anchor = tmp_path / "log" / "r.jsonl", tmp_path / "a.jsonl"
    keys = {}
    for name in ("old", "new"):
        private, public = tmp_path / f"{name}.priv", tmp_path / f"{name}.pub"
        subprocess.run([binary, "keygen", "--out", str(private), "--public-out", str(public)], check=True, capture_output=True)
        keys[name] = (private, public.read_text(encoding="utf-8").strip())
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-demo-v1"}))

    class Client:
        def __call__(self, url, payload, headers):
            return {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}

    os.environ["GROQ_API_KEY"] = "k"
    try:
        run_turn("before", "groq", Kernel(policy, log, binary=binary, anchor=anchor, sign_key=keys["old"][0]), client=Client())
        limit_expected = json.loads(log.read_text().splitlines()[-1])["receipt_id"]
        run_turn("after", "groq", Kernel(policy, log, binary=binary, anchor=anchor, sign_key=keys["new"][0]), client=Client())
    finally:
        del os.environ["GROQ_API_KEY"]

    def sh(script, **extra):
        env = {**os.environ, "SMOKE_SOURCE_ONLY": "1", "CTL": binary, "PREFIX": str(ROOT),
               "VERIFIER": str(ROOT / "verifier" / "ickverify.py"), **extra}
        return subprocess.run(["bash", "-c", f'source "{SMOKE}"; {script}'], capture_output=True, text=True, env=env, cwd=tmp_path)

    first = sh(f'receipt_at "{log}" first')
    last_before_switch = limit_expected
    assert first.stdout.strip() == json.loads(log.read_text().splitlines()[0])["receipt_id"], first.stderr
    assert sh(f'receipt_at "{log}" last').stdout.strip() == json.loads(log.read_text().splitlines()[-1])["receipt_id"]

    limited, early, unlimited = tmp_path / "limited", tmp_path / "early", tmp_path / "unlimited"
    sh(f'write_limited_trust "{limited}" "{keys["old"][1]}" "{last_before_switch}" "{keys["new"][1]}"')
    sh(f'write_limited_trust "{early}" "{keys["old"][1]}" "{json.loads(log.read_text().splitlines()[0])["receipt_id"]}" "{keys["new"][1]}"')
    sh(f'write_unlimited_trust "{unlimited}" "{keys["old"][1]}" "{keys["new"][1]}"')
    assert limited.read_text(encoding="utf-8").splitlines()[0] == f'{keys["old"][1]} through {last_before_switch}'

    good = sh(f'verify_files "{log}" "{anchor}" "{limited}"')
    assert good.returncode == 0 and good.stdout.startswith("VERIFIED"), good.stdout
    too_early = sh(f'verify_files "{log}" "{anchor}" "{early}"')
    assert too_early.returncode != 0 and "retired or revoked" in too_early.stdout

    thief_log, thief_anchor = tmp_path / "thief.log", tmp_path / "thief.anchor"
    thief_log.write_bytes(log.read_bytes())
    thief_anchor.write_bytes(anchor.read_bytes())
    forged = sh(f'forge_with_key "{keys["old"][0]}" "{policy}" "{thief_log}" "{thief_anchor}"')
    assert forged.returncode == 0, forged.stderr
    assert len(thief_log.read_text().splitlines()) == len(log.read_text().splitlines()) + 1
    assert sh(f'verify_files "{thief_log}" "{thief_anchor}" "{unlimited}"').returncode == 0  # accepted without the limit
    refused = sh(f'verify_files "{thief_log}" "{thief_anchor}" "{limited}"')
    assert refused.returncode != 0 and "retired or revoked" in refused.stdout  # refused with it


def test_the_smoke_test_runs_the_key_switch_after_the_probes_and_cleans_up_its_secrets():
    text = SMOKE.read_text(encoding="utf-8")
    body = text[text.index("apply() {"):text.index("summary() {")]
    assert body.index("  probes\n") < body.index("  key_switch\n") < body.index("  summary\n")
    switch = text[text.index("key_switch() {"):text.index("probes() {")]
    assert 'rm -rf "$WORK"' in switch and "chmod 700 \"$WORK\"" in switch  # the old private key copy is removed
    assert 'forge_with_key "$WORK/old.priv" /etc/ick/policy.json "$WORK/thief.log"' in text  # never the live log
    assert "ks_thief" in switch and "ks_too_early_refused" in switch and "verify_published" in switch
