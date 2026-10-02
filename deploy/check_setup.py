#!/usr/bin/env python3
"""Audit a deployment of the signer service against the separation it is supposed to give you.

    python3 deploy/check_setup.py [--signer ick-signer] [--nova nova] [--publisher ick-publisher] \\
                                  [--operator YOURLOGIN] [--nova-env /etc/nova/nova.env]

The signer service is only worth running if Nova's account cannot read the key, change the policy,
write the log or the anchor, or approve its own requests, and if the publisher cannot do what Nova
can. This checks that from the file system: for each file or directory it works out, from owner,
group, mode and the accounts' group memberships, who can read it and who can write it, and says
FAIL where the answer is wrong. Run it after installing, and again after any change.

What it does NOT see: POSIX ACLs, file capabilities, SELinux/AppArmor, read-only mounts, systemd
sandboxing, or anything a person with root can do. Treat a pass as "the ordinary permissions are right",
not as proof of isolation. Anything missing is reported as SKIP, never as a pass.

Exit status: 0 nothing failed, 1 at least one FAIL, 2 could not run.
"""

from __future__ import annotations

import argparse
import grp
import os
import pwd
import stat
import sys
from dataclasses import dataclass
from typing import List, Optional, Sequence, Set


@dataclass(frozen=True)
class Account:
    name: str
    uid: int
    gids: frozenset


def account(name: str) -> Optional[Account]:
    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        return None
    gids = {entry.pw_gid} | {g.gr_gid for g in grp.getgrall() if name in g.gr_mem}
    return Account(name, entry.pw_uid, frozenset(gids))


def mode_allows(who: Account, mode: int, owner: int, group: int, want: int) -> bool:
    """Do the owner/group/other permission bits give `who` all of `want` (4 read, 2 write, 1 execute)?
    Root can do anything. This is the classic Unix rule and ignores ACLs."""
    if who.uid == 0:
        return True
    if who.uid == owner:
        bits = (mode >> 6) & 7
    elif group in who.gids:
        bits = (mode >> 3) & 7
    else:
        bits = mode & 7
    return bits & want == want


def can(who: Account, path: str, want: int) -> Optional[bool]:
    """Can `who` read (4) or write (2) `path`? Every directory above it must be searchable (x).
    None if the path does not exist."""
    try:
        target = os.stat(path)
    except FileNotFoundError:
        return None
    parts, parent = [], os.path.dirname(os.path.abspath(path))
    while True:
        parts.append(parent)
        if parent == os.path.dirname(parent):
            break
        parent = os.path.dirname(parent)
    for directory in parts:
        st = os.stat(directory)
        if not mode_allows(who, st.st_mode, st.st_uid, st.st_gid, 1):
            return False
    return mode_allows(who, target.st_mode, target.st_uid, target.st_gid, want)


def can_create_in(who: Account, directory: str) -> Optional[bool]:
    """Can `who` create or replace files in `directory` (write + search)?"""
    try:
        st = os.stat(directory)
    except FileNotFoundError:
        return None
    return mode_allows(who, st.st_mode, st.st_uid, st.st_gid, 3) and can(who, directory, 1) is not False


@dataclass
class Result:
    status: str  # PASS, FAIL, SKIP
    what: str
    why: str = ""


class Audit:
    def __init__(self) -> None:
        self.results: List[Result] = []

    def add(self, status: str, what: str, why: str = "") -> None:
        self.results.append(Result(status, what, why))

    def expect(self, got: Optional[bool], want: bool, what: str, why_if_wrong: str, path: str) -> None:
        if got is None:
            self.add("SKIP", what, f"{path} does not exist yet")
        elif got == want:
            self.add("PASS", what)
        else:
            self.add("FAIL", what, why_if_wrong)


def audit(args: argparse.Namespace, resolve=account) -> Audit:
    a = Audit()
    names = {"signer": args.signer, "nova": args.nova, "publisher": args.publisher}
    accounts = {role: resolve(name) for role, name in names.items()}
    operator = resolve(args.operator) if args.operator else None
    for role, acc in accounts.items():
        if acc is None:
            a.add("FAIL", f"the {role} account '{names[role]}' exists", "no such user (see sysusers.d)")
    if len({n for n in names.values()}) < 3:
        a.add("FAIL", "the signer, Nova and the publisher are three different accounts",
              "two roles share an account, so one compromise reaches both")
    else:
        a.add("PASS", "the signer, Nova and the publisher are three different accounts")
    signer, nova, pub = accounts["signer"], accounts["nova"], accounts["publisher"]
    if signer is None or nova is None or pub is None:
        return a

    cannot = lambda path, who, bit, label, kind: a.expect(  # noqa: E731
        _neg(can(who, path, bit)), True, f"{who.name} cannot {kind} {label}",
        f"{who.name} can {kind} it: {path}", path)

    # the key: the signer only
    key = args.key
    a.expect(can(signer, key, 4), True, "the signer can read its signing key", "it cannot", key)
    for who in (nova, pub):
        cannot(key, who, 4, "the signing key", "read")
    if operator:
        cannot(key, operator, 4, "the signing key", "read")
    st = _stat(key)
    if st is not None:
        a.expect(not (st.st_mode & 0o077), True, "the signing key is mode 0600 or tighter",
                 f"mode is {oct(st.st_mode & 0o777)}", key)
        a.expect(st.st_uid == signer.uid, True, "the signing key is owned by the signer",
                 "someone else owns it and can chmod it", key)

    # the policy, and the trusted keys: nobody who is governed or publishes may change them
    for label, path in (("the policy", args.policy), ("the trusted-keys file", args.trusted_keys)):
        for who in (signer, nova, pub):
            cannot(path, who, 2, label, "write")
    for directory in sorted({os.path.dirname(args.policy), os.path.dirname(args.trusted_keys)}):
        for who in (signer, nova, pub):
            a.expect(_neg(can_create_in(who, directory)), True, f"{who.name} cannot replace files in {directory}",
                     "it could swap the policy or the keys for its own", directory)

    # the log and the anchor: only the signer writes; the publisher reads
    for label, path in (("the receipt log", args.log), ("the anchor", args.anchor)):
        a.expect(can(signer, path, 2), True, f"the signer can write {label}", "it cannot", path)
        for who in (nova, pub):
            cannot(path, who, 2, label, "write")
        d = os.path.dirname(path)
        for who in (nova, pub):
            a.expect(_neg(can_create_in(who, d)), True, f"{who.name} cannot create or replace files next to {label}",
                     f"{who.name} can write in {d}, so it could replace the file", d)
    a.expect(can(pub, args.anchor, 4), True, "the publisher can read the anchor", "it cannot, so it cannot publish",
             args.anchor)
    a.expect(can(pub, args.log, 4), True, "the publisher can read the log", "it cannot, so it cannot check it first",
             args.log)
    cannot(args.anchor, nova, 4, "the anchor", "read")
    if operator:
        a.expect(can(operator, args.log, 4), True, "the operator can read the log", "add yourself to ick-audit",
                 args.log)
        a.expect(can(operator, args.anchor, 4), True, "the operator can read the anchor",
                 "add yourself to ick-audit", args.anchor)

    # human approvals: only the operator writes them; Nova and the signer read
    for who in (nova, signer, pub):
        cannot(args.approvals, who, 2, "the approvals file", "write")
        cannot(args.denials, who, 2, "the denials file", "write")
        a.expect(_neg(can_create_in(who, os.path.dirname(args.approvals))), True,
                 f"{who.name} cannot create files in {os.path.dirname(args.approvals)}",
                 "it could add an approvals or denials file of its own", os.path.dirname(args.approvals))
    a.expect(can(nova, args.approvals, 4), True, "Nova can read the approvals file", "it cannot", args.approvals)
    a.expect(can(signer, args.approvals, 4), True, "the signer can read the approvals file", "it cannot",
             args.approvals)

    # the socket: Nova yes, the publisher no
    a.expect(can(nova, args.socket, 2), True, "Nova can reach the signer's socket", "it cannot", args.socket)
    cannot(args.socket, pub, 2, "the signer's socket", "write to")

    # publisher secrets
    for who in (nova, signer):
        cannot(args.deploy_key, who, 4, "the publisher's deploy key", "read")
    a.expect(can(pub, args.deploy_key, 4), True, "the publisher can read its deploy key", "it cannot", args.deploy_key)

    # Nova's environment
    if args.nova_env:
        try:
            text = open(args.nova_env, encoding="utf-8").read()
        except OSError:
            a.add("SKIP", "Nova's environment file names no policy, key or kernel", f"cannot read {args.nova_env}")
        else:
            banned = sorted({v for v in ("NOVA_ICK_POLICY", "NOVA_ICK_SIGN_KEY", "NOVA_ICK_BIN", "INFINITY_SIGN_KEY")
                             if any(line.split("=", 1)[0].strip() == v for line in text.splitlines()
                                    if "=" in line and not line.lstrip().startswith("#"))})
            if banned:
                a.add("FAIL", "Nova's environment file names no policy, key or kernel",
                      f"it sets {', '.join(banned)}: the service owns those")
            else:
                a.add("PASS", "Nova's environment file names no policy, key or kernel")
    return a


def _neg(value: Optional[bool]) -> Optional[bool]:
    return None if value is None else not value


def _stat(path: str) -> Optional[os.stat_result]:
    try:
        return os.stat(path)
    except FileNotFoundError:
        return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="check_setup", description=__doc__.split("\n\n")[0])
    parser.add_argument("--signer", default="ick-signer")
    parser.add_argument("--nova", default="nova")
    parser.add_argument("--publisher", default="ick-publisher")
    parser.add_argument("--operator", help="the human's login, to check they can read what they need")
    parser.add_argument("--key", default="/etc/ick/signing.priv")
    parser.add_argument("--policy", default="/etc/ick/policy.json")
    parser.add_argument("--trusted-keys", default="/etc/ick/trusted-keys.pub")
    parser.add_argument("--log", default="/var/lib/ick/log/receipts.jsonl")
    parser.add_argument("--anchor", default="/var/lib/ick/anchor/anchor.jsonl")
    parser.add_argument("--approvals", default="/etc/ick/human/approvals.jsonl")
    parser.add_argument("--socket", default="/run/ick/ick.sock")
    parser.add_argument("--deploy-key", default="/etc/ick-publisher/deploy_key")
    parser.add_argument("--nova-env", default="/etc/nova/nova.env")
    args = parser.parse_args(argv)
    args.denials = args.approvals + ".denials"
    if os.name != "posix":
        print("this audit reads Unix accounts and modes; run it on the server", file=sys.stderr)
        return 2
    report = audit(args)
    width = max(len(r.what) for r in report.results)
    for r in report.results:
        line = f"{r.status:4}  {r.what:<{width}}"
        print(line + (f"  -- {r.why}" if r.why else ""))
    failed = sum(r.status == "FAIL" for r in report.results)
    skipped = sum(r.status == "SKIP" for r in report.results)
    passed = sum(r.status == "PASS" for r in report.results)
    print(f"\n{passed} passed, {failed} failed, {skipped} skipped. "
          "Ordinary permissions only: no ACLs, capabilities, mounts or security modules were examined.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
