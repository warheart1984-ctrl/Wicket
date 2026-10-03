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
the arguments). The kernel does not interpret it. It is hashed into the receipt like every other field, so
the `allow` is now an authorization of *that exact call*. Message text is still never included, only its hash.

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

### 3. New entry kinds, in the witness's own chain
Witness entries are signed by the witness key and hash-linked like receipts, and live in a separate log, so a
taken-over Nova or even a taken-over signer cannot forge them (and vice versa).

- `execution`: the allow receipt id, the observed `call_digest`, a witness-clock time, status.
- `divergence`, with a kind:
  - `mismatch`: observed digest differs from the authorized one.
  - `unauthorized`: a call was seen with no receipt, or the receipt was a deny or still pending.
  - `reused`: one allow was used for more than one call.
  - `unexecuted`: an allow expired with no execution (informational; not by itself a violation).
  - `witness-silent`: the witness's own heartbeat stopped (so absence of divergence means nothing).

### 4. Verifier
`verifier/ickverify.py` gains an optional `--witness-log` and `--witness-keys`. It joins the two logs by
receipt id and reports: executions whose digest differs from the allow's `call_digest`, executions with no
allow, allows used more than once, allows with no execution, every divergence entry, and gaps in the witness
heartbeat. As today, trusted keys must come from outside the log's host.

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
8. **Late use.** Execute after the allow's expiry. Expect refusal or `mismatch`.

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
