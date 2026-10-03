# Execution binding: design for review (not built)

**Status:** a proposal, written so it can be attacked on paper before any code exists. Nothing here is
implemented or tested. The aim is to close, as far as one can, the gap named in `THREAT_MODEL.md`: a valid
receipt proves what was *asked* and what the policy *said*, not that the action actually carried out was the
one authorized.

## The five stages

| Stage | Meaning | Does Wicket prove it today? |
|---|---|---|
| Proposed | A caller described an action to the gate | Yes: recorded and hashed |
| Authorized | The kernel judged that description under the policy | Yes: signed, chained receipt |
| Dispatched | A concrete call was actually sent | No |
| Executed | The target did it | No |
| Observed | An independent party saw the effect | No |

This design targets *dispatched* and, where a vantage point allows, *executed*. It does not reach *observed
effect* in general (see Limits).

## The gap, as an attack

1. The attacker (a taken-over caller, or a lying one) describes an action as "a harmless read of X".
2. The kernel allows it. The log holds a perfectly valid `allow`.
3. The caller then performs a different action (a write to Y). Every receipt still verifies.

Today nothing connects the *description* the kernel judged to the *call* that left the machine.

## Proposal

### 1. Commit to the concrete call, not only the description
The proposal gains one field, `call_digest`: a SHA-256 over a canonical encoding of the concrete call as it
will go out (for a network call: method, host, path, a hash of the body; for a tool: tool name and a hash of
the arguments). The kernel does not interpret the digest itself, but the signer computes it (see below). It is hashed into the receipt like every other field, so
the `allow` is now an authorization of *that exact call*. Message text is still never included, only its hash.

#### Who supplies the digest, and the lie at proposal time
If Nova supplies both the description and the digest, a lying caller can pair "a harmless read" with the
digest of a harmful write. The kernel allows it, and the witness later runs the write faithfully because the
digests match. Binding stops *substitution after approval*. It does not stop *lying at proposal time*.

So the description must not be taken on trust where it can be derived:
- Nova sends the signer the **concrete call**, not just a digest. For each **known call shape** (a registry of
  shapes such as "HTTPS request to provider X", "local-model tool: explain"), the signer derives `effect` and
  `target` from the call itself and computes `call_digest` itself.
- If the caller's description disagrees with what was derived, the decision is `deny`, recorded as such.
- A call whose shape is not in the registry cannot be derived. It is denied, or sent to a human, never allowed
  on the caller's word. The registry is therefore part of the trusted code and needs the same care as the policy.
- Limit: derivation covers what the call says it does (method, host, path, tool). It cannot see side effects
  the target has beyond that.

#### One receipt per call
Each concrete call needs its own receipt. A receipt covering a short plan is out of scope for now, because
later steps depend on earlier results, so a plan authorizes calls nobody has seen yet. Revisit only with a
written reason.

#### The state an approval was based on
A decision and an approval are made against some state S0. Executing against S1 is the stale-approval attack.
The proposal gains an optional `state_ref`: a hash or version string of the state the decision relied on,
supplied by the caller where the target exposes one (a record version, an ETag, a simulation tick). The witness
reads the target's current `state_ref` just before dispatch and refuses, or records `late`, if it differs. Where
the target exposes no version, there is no `state_ref` and this protection does not exist; say so rather than
imply it.

#### Which bytes are hashed
Canonicalization bugs enter through chunking, compression and encoding, so the bytes are fixed in advance:
- The body hash covers the **decoded request body bytes**, exactly as the target will receive them, after
  removing transfer chunking and content compression, with no re-encoding, in order. Chunk boundaries never
  matter.
- Method, scheme, host, port, the path and query as sent, and a fixed short list of headers that change
  meaning (content type, content encoding, authorization *presence* but never its value) go into the digest in
  a fixed order with length prefixes, so fields cannot run together.
- A body that is not known before dispatch (a live stream) **cannot be bound in advance**. Such a call is
  denied, or must be buffered up to a size cap and hashed whole; above the cap it is denied. A digest recorded
  after the fact is evidence, not authorization.
- The specification is written once, and a second implementation (as the verifier has) is checked against it
  with the equivalent-encoding attacks below.

### 2. A witness Nova does not control
A new component, the **witness**, runs under its own account (ideally its own host), with its own signing key,
separate from the signer's. Two modes; the second is the weaker fallback.

- **Executor mode (preferred).** Nova does not call the target. It hands the witness the concrete call and the
  receipt id. The witness recomputes `call_digest`, then checks, using read-only access to the log: the receipt
  exists and chains, its verdict is `allow`, its `call_digest` matches, it has not expired, and it has not been
  used. Only then does it perform the call, and it writes a signed `execution` entry. A mismatch is refused and
  written as a signed `divergence` entry. This only holds if Nova has *no other route* to the target (network
  egress allowed only from the witness). That is a deployment control, not something code can enforce.
- **Observer mode.** Nova still makes calls. The witness sits on the egress path (proxy, firewall or host audit
  log) and records every call it sees. A reconciler compares what was seen to what was authorized.

#### Who consumes an allow
"Not used yet" needs exactly one owner. In executor mode the **witness is the only place an allow is consumed**,
and the consumption is an entry in the witness's own chain. Nova's use counting is not relied on, which avoids
the approval-replay problem Nova has today (see limit 4 in `THREAT_MODEL.md`). Consumption is recorded
*before* the call is made, so a crash after dispatch cannot leave an allow that looks unused. In observer mode
nothing can be consumed, only noticed afterwards, which is why it is the weaker mode.

### 3. New entry kinds, in the witness's own chain
Witness entries are signed by the witness key and hash-linked like receipts, and live in a separate log, so a
taken-over Nova or even a taken-over signer cannot forge them (and vice versa).

- `execution`: the allow receipt id, the observed `call_digest`, an attempt number, the observed `state_ref`
  if any, a witness-clock time, and a status (`started`, `completed`, `failed`).
- `divergence`, with a kind:
  - `mismatch`: observed digest differs from the authorized one.
  - `unauthorized`: a call was seen with no receipt, or the receipt was a deny or still pending.
  - `reused`: one allow was used for a *different* call, or for the same call after it completed.
  - `late`: executed after the state that justified the approval changed (`state_ref` differs), or after expiry.
  - `partial`: a call that was recorded as started and never reached `completed` or `failed`.
  - `unexecuted`: an allow expired with no execution (informational; not by itself a violation).
  - `witness-silent`: the witness's own heartbeat stopped (so absence of divergence means nothing).

### 4. Verifier
`verifier/ickverify.py` gains an optional `--witness-log` and `--witness-keys`. It joins the two logs by
receipt id and reports: executions whose digest differs from the allow's `call_digest`, executions with no
allow, allows used more than once, allows with no execution, every divergence entry, and gaps in the witness
heartbeat. As today, trusted keys must come from outside the log's host.

#### Retries are not replays
A retry after a failed or partial call looks like reuse. The rule: an allow permits the **same digest** to be
attempted again, up to a small limit written in the policy (default 1 retry), and only while no attempt has
`completed`. Each attempt is its own `execution` entry with an attempt number, so a retry is visible as a
retry. A different digest, an attempt after `completed`, or attempts past the limit are `reused`.

## Attacks the design must survive (these become tests)

1. **The core attack.** Get an allow for a read, then execute a different call. Expect `mismatch` (or refusal
   in executor mode).
2. **Equivalent-but-different encoding.** Same call with reordered fields, case or whitespace changes, to
   defeat or confuse canonicalization. Expect one digest for one call, and a different digest for any change.
3. **Replay.** Use one allow twice. Expect `reused`.
4. **No receipt.** Call the target directly. Expect `unauthorized` (observer) or no route (executor).
5. **Substituted receipt.** Present an allow issued for a different call. Expect `mismatch`.
6. **Forged witness entry.** Run as the Nova account and try to write the witness log or read its key. Expect
   the same account-separation probe the signer service already passes.
7. **Silence.** Stop the witness. Expect the heartbeat gap to show, and in executor mode, no calls.
8. **Late use.** Execute after the allow's expiry. Expect refusal or `late`.
9. **Lying at proposal time.** Describe a write as a read, with the digest of the write. Expect the signer to
   derive `write` from the call and deny the disagreement.
10. **Unknown call shape.** Send a call the registry does not know. Expect deny or a human, never allow.
11. **Stale approval.** Approve against state S0, change the target to S1, then execute. Expect `late`.
12. **Chunked, compressed or streamed body.** The same bytes sent in different chunkings and encodings must
    give one digest; an unbounded stream must be denied, not hashed after the fact.
13. **Retry versus replay.** One retry after a failure is accepted and numbered; a second completion, or a
    different digest, is `reused`.
14. **Crash after consume.** Kill the witness between consuming an allow and dispatching. Expect the allow to
    show as consumed (and `partial`), never as unused and re-usable.

## Limits, stated in advance

- **A digest binds the call, not its effect.** A call that looks like a read but has side effects on the
  target passes. Binding to effect needs knowledge of the target, which the witness does not have.
- **Vantage point.** The witness sees only what crosses its path. Effects inside a simulation, or on the local
  machine, are invisible to a network witness.
- **Bypass.** In observer mode a divergence is detected after the fact, not prevented. In executor mode the
  guarantee is only as good as the egress restriction.
- **Canonicalization is now security-critical.** A bug there is a bypass, so it needs one specification and
  a second implementation, as the verifier has.
- **Compromised witness.** A taken-over witness host can sign false executions. This moves trust, it does not
  remove it. Two independent witnesses would help; that is out of scope here.
- **Time.** The witness's clock is another unproven clock. Event, receipt, execution and observation times
  remain distinct things this design does not reconcile.
- **Cost.** Executor mode puts the witness in the availability path, as the signer already is.

## Questions for the reviewer

1. In executor mode, what is the cheapest way you would route around the witness, short of compromising it?
2. Is a call digest the right granularity, or would you bind something coarser (target and effect) or finer?
3. Which of the five stages would you want proven *first* in a command or simulation setting?
4. What would you treat as a divergence that this list does not name?
5. Is one receipt per call acceptable for dependent agent actions, or does a bounded plan receipt have a safe
   form?
6. Is a registry of known call shapes workable, or does every new tool become a security review?
