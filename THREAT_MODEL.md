# What the receipts do and do not prove

This is the one page to read before relying on `infinity-core` for anything that matters. It says who
the system defends against, what it cannot defend against, and how a stranger can check a log without
trusting anyone who wrote it. Every claim here is either tested (the test is named) or listed as a gap.

## The claim, in one paragraph

Every request that goes through the gate is judged by a small deterministic kernel that never calls a
model. The verdict (`allow`, `deny`, or "wait for a human") is written to an append-only log as a
receipt whose id is a hash of its contents and of the receipt before it. When a model call finishes,
an outcome is chained in, pointing at the `allow` that permitted it. Entries can be signed with an
Ed25519 key, and the log's length and newest id are recorded in an *anchor* that can be published
somewhere the log's writer cannot edit. A reader can then tell whether the history they were given is
the history that was written, and whether it is complete up to the newest anchor.

## What a reader can check, and what they must bring

```bash
python verifier/ickverify.py LOG --anchor ANCHOR --trusted-keys KEYS --require-signatures
```

`verifier/ickverify.py` is one file, standard library only. It does not run `infinityctl`; it recomputes
every hash and checks every signature itself, so a bug or a swapped binary in the Rust kernel cannot make
a bad log look good. It is a second implementation written by the same author, checked against the Rust
verifier on real logs, on dozens of kinds of deliberate damage, and on random single-character changes
(`tests/test_standalone_verifier.py`). Two implementations agreeing is better than one. It is not an
independent audit.

The reader must supply two things the log cannot supply for itself:

| Input | Where it must come from | If it comes from the log's own machine |
|---|---|---|
| **Trusted keys** | A file you got from the operator over a channel an attacker on the log host does not control | A forger just adds their own key. Signatures then prove nothing |
| **Anchor** | A copy you fetched yourself from the published anchor repository | An attacker who can edit the log can edit the anchor next to it, so deleted entries go unnoticed |

## Who the system is built to stop

| An attacker who can... | Stopped by | Result |
|---|---|---|
| Edit, insert, reorder or delete entries **in the middle** of the log | The hash chain | Detected, with or without an anchor or keys (every kind of damage is a test case) |
| Delete the **newest** entries | The anchor, if you hold a copy the attacker could not edit | Detected only with such an anchor. A log checked alone cannot tell it was cut short |
| Edit the log **and** the local anchor and signatures stay valid for an earlier state | The *published* anchor | A rollback to an earlier genuine state is invisible to the local checks. Only the published copy catches it (tested: local passes, published fails) |
| Write the log files but **not read the key** | Signatures | Cannot forge or alter entries without the key |
| Reach the model API through Nova | The gate fails closed | Missing binary, unreadable policy or any kernel error means no call |
| Call the approval path as the model | There is no HTTP route that approves; the operator screen is a separate localhost process with a token | A client cannot approve its own request (tested) |
| Reuse an approval for a different request | Approvals are bound to the request's hash, expire, and have a use limit | A changed request is a new request. Reuse of the same one is bounded |

## Who it does *not* stop

These are real limits, not fine print.

1. **A lie about what is being done.** The kernel judges the description it is given. If the process
   that calls it says "a harmless read" and then does something else, the log faithfully records the
   harmless read. The log proves what was *asked* and what the policy *said*, not what *happened*.
   Outcomes ("completed", the hashes) are the caller's claim; they are signed and chained, not verified.
2. **Not asking at all.** A taken-over caller can skip the gate. The log then has gaps, but nothing in
   the log shows a gap. Absence of an entry is never evidence.
3. **Whoever holds the signing key.** In the basic setup the key is a file on the machine that writes
   the log, readable by the Nova process. Anyone who takes over that process can sign forgeries. The
   optional signer service (`runtime/ick_service.py`, separate account, Unix socket) takes the key, the
   policy and the log away from Nova, and Nova can then no longer forge a verdict. It still cannot
   stop the lie in (1) or the silence in (2), and a compromised service host defeats everything.
4. **Approvals replayed within their lifetime.** Uses are counted by Nova. With the signer service on, a
   taken-over Nova can replay an approval that still has uses left until it expires.
5. **The human in the loop.** An approval shows action, target, effect, risk and facts about the request,
   not the whole request. The screen's token is the only login: anyone who can read it or the browser can
   approve or deny. A tired human approving what they did not understand is outside the system.
6. **The clock.** `issued_at` is supplied by the caller. A signature proves the signer asserted that
   time, not that it was true.
7. **A stolen key stays trusted.** There is no revocation and no "valid until" for keys; a leaked key is
   trusted until someone edits the trusted-keys file by hand.
8. **The provider.** The model provider can return anything. The outcome records a hash of the reply;
   it does not show the model produced it, or what a user was shown.
9. **The publisher.** The anchor publisher must run as a different user from Nova with push credentials
   Nova lacks, or one compromise reaches both. Its status file can be faked by a compromised publisher.
10. **Availability.** Failing closed means anyone who can stop the kernel or the signer service stops all
    governed calls. That is deliberate.

## What a "VERIFIED" result means

The verifier prints this with every run, because the word is easy to over-read:

- The entries are unchanged since written, in order, with none inserted or removed in the middle.
- None were cut from the end *if* the anchor you gave is genuine and current. It also tells you when the
  newest entries are not anchored yet, when no anchor was given, and when signatures were not checked.
- With trusted keys, each signed entry was signed by a holder of a key you chose to trust.
- It does **not** show that what was done matched what was asked, that an outcome is true, that the clock
  was right, or that a key was never stolen. An empty or unsigned log can still "verify"; the notes it
  prints say so.

## Not built, not verified

- No independent security review of any of this. It has been tested by its author.
- The anchor publisher has only been tested against local git repositories, not a hosted service.
- Windows: no file locking for the last use of an approval, and no key-file permission check (Unix only).
  CI runs the suites there; it skips the tests of Unix-only behaviour.
- No hardware keys or key store, no key revocation, no multi-party signing.
- The kernel starts a process per decision. Throughput has not been measured.
- `deploy/` has systemd units, accounts and an audit script for the signer, Nova and the publisher. They
  pass `systemd-analyze`, their commands run in tests, and `deploy/smoke-test.sh` has run them once under a
  booted systemd with real accounts on one Linux Mint machine (25 of 25 checks, with the separation probed
  as the real users). Other distributions and setups are untested, and the audit reads ordinary permissions only (no ACLs, capabilities or
  security modules). Nothing monitors that the services keep running.

## Questions to ask before relying on it

1. Who holds the signing key, and could the thing being governed read it?
2. Where is the published anchor, and who checks it against the log, how often?
3. Where did the trusted-keys file come from, and could the log host change it?
4. What would an attacker gain by describing an action falsely to the gate? (This system cannot answer that.)
5. What happens to the product if the kernel or signer is unreachable for an hour?
