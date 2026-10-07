# Executor mode

Executor mode is the witness in `runtime/witness.py`. The caller hands it a concrete call and an
allow receipt id. The witness decides whether that call may run, and it is the component that
performs the call. Nova does not hold the witness signing key: `NOVA_ICK_WITNESS` is the socket
of `python -m runtime.witness_service`, which owns that key and the witness log.

The witness requirement is on by default. You do not set `NOVA_ICK_POLICY` to turn it on. A
known-shape provider call from `run_turn` or `python -m runtime` is sent by a witness or not
sent at all. With no witness configured, the provider client is not called. The kernel may
still record a decision. On that path the proposal is the runtime's own description (effect
`read`, target the provider name), not a derived `call_digest`, and there is no outcome
because nothing was sent.

`WICKET_ALLOW_DIRECT_CALLS=1` is an explicit opt-out for local development. It is off when
unset, and any other value is off. When it is exactly `1`, `run_turn` sends the provider call
from this process and writes a warning to stderr every time. That path does not go through
the witness and does not derive the call. The same variable is the only escape for Nova model
HTTP, and only while Nova's policy is unset. Do not set it in a deploy unit, a systemd service,
or a production environment.

Gossip uses the same path as Nova's known-shape routes. Each peer gets a concrete
`https_request`, and effect, target, and `call_digest` are derived from it. The witness
sends the call only after a matching allow. No allow, or no witness: the peer is not
contacted. `WICKET_ALLOW_DIRECT_CALLS` does not apply to gossip. An unknown shape is denied
(`UNKNOWN_CALL_SHAPE`) and not sent.

Nova model HTTP sends nothing unless a policy and a witness are both configured. A policy is
`NOVA_ICK_POLICY` or `NOVA_ICK_SERVICE`. A witness is `NOVA_ICK_WITNESS` (the socket of
`python -m runtime.witness_service`) or the in-process witness tests install. With both of
those policy variables unset, Nova does not call the provider client. A witness with no
policy is not enough: there is no allow to check, so nothing is sent. A policy with no
witness is the fail-closed path: nothing is sent. `WICKET_ALLOW_DIRECT_CALLS=1` is the only
escape, and it does not apply once a policy is set. It warns on stderr every time, does not
derive a `call_digest`, and does not let gossip skip an allow.

When the policy and the witness are both configured, a known-shape provider call or
local-model tool is sent by the witness. Effect, target, and `call_digest` are derived from
the concrete call. A provider chat is an HTTP POST, so the derived effect is `write`. A
policy that allows only reads will not let that call through. Streaming a known-shape
provider call is refused while a witness would be required: the witness binds one request
body, not a stream.

A caller who can still reach the target without the witness is outside this control. That is a
deployment limit (egress), not something this code enforces.

## What it checks

Before anything is sent:

1. It recomputes `call_digest` from the call, using `runtime/call_binding.py`.
2. It runs `infinityctl verify-log` on the receipt log (signatures required). If that fails, the
   call is `unauthorized` and is not sent.
3. The receipt must exist and its verdict must be `allow`. A deny, a wait, or a missing id is
   `unauthorized`.
4. The recomputed digest must equal the receipt's `call_digest`. Anything else, including an
   unknown call shape, is `mismatch`. A mismatch does not use up the allow, so the call that was
   actually allowed can still be run once.
5. The allow must be unused. A second attempt is `reused`.
6. `issued_at` must be RFC3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`) and not older than `--allow-ttl`
   seconds (default 3600) on the witness clock. Otherwise the call is `late`. A timestamp this
   program cannot parse is `late`.

Only then does it append a signed `started` entry. That entry consumes the allow. Then it
performs the call. Then it appends `completed`, or `failed` if the send raised. One allow, one
execution. A failure does not grant a retry. A crash after `started` leaves the allow consumed;
there is no separate `partial` entry. The bare `started` line is that record.

Divergence entries (`mismatch`, `unauthorized`, `reused`, `late`) are signed and chained in the
witness log. They do not consume an allow.

The witness log is a different file from the receipt log, signed with a different key
(`infinityctl witness-append`, `infinityctl witness-verify`). `witness-verify` checks the hash
chain and requires every entry's signature. It does not apply `through` key retirement. A trusted
keys file that uses `through` is refused, so a retirement does not look enforced when it is not.

## What the signer does

When `runtime/ick_service.py` receives `evaluate` with a `call`, it derives `effect` and `target`
from the call, computes `call_digest`, and puts those on the proposal before the kernel runs.

- If the caller's effect, target, or a supplied `call_digest` disagrees, the decision is `deny`
  with `DESCRIPTION_DISAGREEMENT`. The recorded proposal carries the derived values, so the deny
  describes the call that was sent to the signer.
- A shape the registry does not know is `deny` with `UNKNOWN_CALL_SHAPE`, and no digest is kept.
- If there is no `call`, nothing is derived. Effect, target, and any digest are the caller's
  claim, as before.

The kernel does not interpret `call_digest`. A non-empty `payload.binding_fault` is how the
signer asks for the deny. `UNKNOWN_CALL_SHAPE` is kept as that reason. Any other text is recorded
as `DESCRIPTION_DISAGREEMENT`. That flag cannot produce an `allow`.

`infinityctl evaluate` copies `call_digest` from the proposal onto the receipt and hashes it when
it is present. It does not derive effect or target. Receipts that omit `call_digest` keep the ids
they already had.

Known shapes today:

| Shape | Read | Write | Target |
|---|---|---|---|
| `https_request` | GET, HEAD | POST, PUT, PATCH, DELETE | `scheme://host:port/path` and the query if there is one |
| `local_model_tool` | `explain`, `status` | `code`, `wire` | `local-model-tool:{tool}` |

Other methods, other tools, extra fields, IPv6 hosts, and a body given both as text and as
base64 are unknown shapes. The body in the digest is the exact bytes that are sent. Content
encoding is not decoded, chunking is not undone, and a stream cannot be bound. The authorization
header's value is sent but not hashed; only its presence is. `risk` and `action` are still the
caller's claim.

HTTP dispatch uses `http.client` and does not follow redirects.

## What the verifier checks

`verifier/ickverify.py` is a second implementation of `call_digest` (standard library only; it
does not import `runtime/`). It recomputes the digest only when you pass `--call` with the
concrete call. The receipt log and the witness log do not store the call body, so the verifier
cannot invent the call from a digest. A forged `call_digest`, or a bound call whose allow omits
`call_digest`, fails verification.

`--witness-log` joins executions to allows by receipt id. It reports mismatch, unauthorized,
reused, late, and a bound allow with no execution, and it surfaces divergence entries of those
kinds. `--witness-keys` checks signatures. A witness key file that uses `through` is refused.
The verifier does not apply that cutoff, and it does not look for a heartbeat. Late means the
witness recorded `late`; this program does not invent a second clock.

`User-Agent` is sent on HTTPS calls and is not part of the digest. The authorization header's
value is sent and not hashed; only its presence is. `risk` and `action` are still the caller's
claim.

## What this does not prove

- **Observed effect.** A `completed` entry means this process sent the call and received bytes.
  It does not prove the target changed, or that those bytes are what a third party would have
  seen.
- **Account separation.** These tests run the signer and the witness in one process, with two
  keys. They do not probe two operating-system accounts the way the signer service's account
  test does.
- **Observer mode, `state_ref`, retries, heartbeat, `witness-silent`, `unexecuted`.** Not built.
  Absence of a divergence entry does not mean the witness was watching.
- **The clock.** Expiry uses the witness clock against `issued_at` text. Neither time is proven.
- **A taken-over witness.** Someone who holds the witness key can sign a false execution. The
  split moves trust off Nova. It does not remove it.
- **Egress.** The guarantee holds only when the target cannot be reached except through the
  witness. That restriction is deployment, not code.
- **The local-dev opt-out.** `WICKET_ALLOW_DIRECT_CALLS=1` sends a runtime provider call, or
  a Nova model HTTP call while Nova's policy is unset, with no witness and no derived digest.
  It warns on stderr on every use and is off by default. Any other value is off. It does not
  let gossip skip an allow, and it does not bypass a Nova policy that is already set.
- **A runtime allow with no witness.** `run_turn` can record an allow for its own description
  and then not call the provider. That receipt has no outcome. It is not a send, and it is
  not a derived binding.
