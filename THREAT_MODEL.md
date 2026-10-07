# What the receipts do and do not prove

This is the one page to read before relying on Wicket for anything that matters. It says who
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

Five stages sit under that claim. Proposed and authorized are what a receipt proves. Dispatched
and executed are what executor mode records when a call is sent through the witness
(`docs/executor-mode.md`). Observed effect is not proved: a completed witness entry means this
process sent the call and received bytes, not that the target's state changed.

| Stage | Meaning | Proved? |
|---|---|---|
| Proposed | A caller described an action | Yes, for requests that go through the gate. The description is hashed |
| Authorized | The kernel judged that description | Yes. Signed, chained receipt |
| Dispatched | A concrete call was sent | Only by the witness, and only for calls it actually sends |
| Executed | The target did it | The witness records the bytes it got back. That is not the target's account of what happened |
| Observed | An independent party saw the effect | No |

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

1. **A lie about what is being done, when the call does not go through the witness.** The kernel
   judges the description it is given. If the process that calls it says "a harmless read" and then
   does something else, the receipt log records the harmless read. Outcomes ("completed", the hashes)
   on that log are the caller's claim; they are signed and chained, not verified.
   Executor mode narrows this for Nova's known shapes when the gate is on. The signer, given a
   concrete `call`, derives effect and target and fills in `call_digest`; a disagreement or an
   unknown shape is a deny (`tests/test_execution_binding.py`). The witness recomputes the digest,
   requires a chained unused unexpired allow for that digest, consumes the allow, and only then
   sends the call. A different call is refused and recorded as `mismatch`. Nova model HTTP sends
   nothing unless a policy (`NOVA_ICK_POLICY` or `NOVA_ICK_SERVICE`) and a witness are both
   configured. With both policy variables unset, Nova does not call the provider client. When
   both are set, provider HTTP and the local-model tool go through that witness, and the receipt
   keeps the `call_digest` derived from the concrete call
   (`tests/test_witness_gate.py`, `nova-shell/tests/test_model_http_default.py`).
   `ickverify.py` recomputes `call_digest` when given the concrete call and joins the witness log.
   This is not observed-effect proof. `infinityctl evaluate` without the signer still trusts the
   caller's description. `run_turn` and `python -m runtime` do not call the provider unless a
   witness does, or `WICKET_ALLOW_DIRECT_CALLS=1` is set. That same opt-out is the only escape
   for Nova model HTTP, and only while the policy is unset (local dev only; it warns on stderr
   every use and is off by default; it does not derive a digest and it does not apply to gossip).
   Gossip is a derived `https_request` sent by the witness, or it is
   not sent; an unknown shape is `UNKNOWN_CALL_SHAPE`. See `docs/executor-mode.md`.
1a. **Who is asking is not checked.** Every proposal has an `actor`, but the kernel never reads it and no policy
   rule can mention it: it is recorded and hashed (so it cannot be edited later), not enforced, and not
   authenticated. Nova names the path that is asking (`nova-shell/model-provider`, `nova-shell/local-model-tool`,
   `nova-shell/gossip`), so the log can tell its paths apart, but that is Nova's own claim: a taken-over Nova
   can write any name. The same goes for `target` and `effect`: they are the caller's assertions. Making the
   actor trustworthy needs the signer service to stamp it from the account that connected, and there is
   only one caller of that service today.
1b. **A policy can only restrict.** It can deny an effect or make it wait for a human. It cannot grant. The
   kernel always denies `deploy`, `authority_change` and `audit_delete` before it reads the policy, so the only
   things that can ever be allowed are `read` and `write`. An empty policy (`denied_effects: []`) is the
   *least* restrictive one possible, not a wide-open one, and there is no way to enable `deploy`.
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
7. **A stolen key, until you act.** A key can be limited to an earlier point in the log with
   `<key> through <receipt>` in the trusted-keys file, so entries it signs after that point are refused. The
   limit is a position in the hash chain, not a date (a thief can backdate the time in an entry). It only helps
   once someone notices and edits the file, it is only as honest as the point chosen, and the signer is not
   told its key was retired. There is no automatic revocation and no expiry by date.
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
- It does **not** show observed effect: that the target's state changed. With `--call` it recomputes
  `call_digest` from the call you supply (a forged or omitted digest fails). With `--witness-log` it
  joins executions to allows. It cannot rebuild a call from a digest. It does not show that the clock
  was right, or that a key was never stolen. An empty or unsigned log can still "verify"; the notes it
  prints say so.

## Not built, not verified

- No independent security review of any of this. It has been tested by its author.
- The anchor publisher has only been tested against local git repositories, not a hosted service.
- Windows: no key-file permission check (Unix only). Counting approval uses is locked on both Unix and
  Windows (checked in CI on both). CI runs the suites on Windows and skips the tests of Unix-only behaviour.
- No hardware keys or key store, no automatic key revocation or expiry by date, no multi-party signing.
- The kernel starts a process per decision (about 2 ms), and every decision re-checks the whole log while
  holding its lock, so the cost grows with the log: about 14 ms at 100 entries, 120 ms at 1,000 and 360 ms at
  3,000 (`scripts/benchmark.py`, one 4-core Linux machine). That is a limit on how long one log can run
  before you archive it and start a fresh one, which makes the evidence several logs, not one.
- `deploy/` has systemd units, accounts and an audit script for the signer, Nova and the publisher. They
  pass `systemd-analyze`, their commands run in tests, and `deploy/smoke-test.sh` has run them under a
  booted systemd with real accounts on one Linux Mint machine (37 of 37 checks, with the separation probed
  as the real users and a signing-key switch done on the running services). Other distributions and setups are untested, and the audit reads ordinary permissions only (no ACLs, capabilities or
  security modules). Nothing monitors that the services keep running.

## Questions to ask before relying on it

1. Who holds the signing key, and could the thing being governed read it?
2. Where is the published anchor, and who checks it against the log, how often?
3. Where did the trusted-keys file come from, and could the log host change it?
4. What would an attacker gain by describing an action falsely to the gate? Executor mode answers
   that only for a call the witness itself sends: a different call is refused. It does not answer
   it for a call that never reaches the witness, and it does not show what the target did afterward.
5. What happens to the product if the kernel or signer is unreachable for an hour?
