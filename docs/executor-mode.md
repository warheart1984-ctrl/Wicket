# Executor mode

Executor mode is the witness in `runtime/witness.py`. Nova hands it a concrete call and an allow
receipt id. The witness decides whether that call may run, and it is the component that performs
the call. Nova's existing HTTP routes are not wired through it. A caller who can still reach the
target without the witness is outside this control. That is a deployment limit, not something
this code enforces.

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

## What this does not prove

- **Observed effect.** A `completed` entry means this process sent the call and received bytes.
  It does not prove the target changed, or that those bytes are what a third party would have
  seen.
- **A second digest implementation.** Only `runtime/call_binding.py` computes `call_digest`.
  `verifier/ickverify.py` checks that a digest present on a receipt is inside the receipt hash.
  It does not recompute the digest, and it does not read the witness log.
- **Nova's routes.** Nothing in the HTTP API was switched over to the witness. Skipping the
  witness is still possible wherever the caller can reach the target.
- **Account separation.** These tests run the signer and the witness in one process, with two
  keys. They do not probe two operating-system accounts the way the signer service's account
  test does.
- **Observer mode, `state_ref`, retries, heartbeat, `witness-silent`, `unexecuted`.** Not built.
  Absence of a divergence entry does not mean the witness was watching.
- **The clock.** Expiry uses the witness clock against `issued_at` text. Neither time is proven.
- **A taken-over witness.** Someone who holds the witness key can sign a false execution. The
  split moves trust off Nova. It does not remove it.
- **Egress.** The guarantee holds only when the target cannot be reached except through the
  witness.
