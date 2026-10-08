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

1. The caller presents `Authorization: Wicket <token>` to the signer and to the witness. That
   header is the credential for this process. It is not the Authorization value sent to the
   target. The token is an Ed25519 signature over the claimed caller id, an expiry, a unique
   token id, and the `call_digest`. Both the signer and the witness verify it. The caller id
   that is recorded and hashed is the id in the caller key file for that public key, not the
   caller id string inside the token. The witness computes `call_digest` with the key-file id,
   then checks the signature against that digest. A missing header, a malformed token, an
   expired token (the witness clock; the clock is not proven), an unknown key, a claimed caller
   id that does not match the key file, or a token id that was already used is
   `IDENTITY_UNVERIFIED`. Nothing is sent. Used token ids are stored in a file next to the
   witness log, so a new witness process against the same directory still rejects a replay.
2. A verified caller must have a grant. The policy's `callers` map lists effects, target
   prefixes, and the risk and action for that caller id. The signer sets risk and action from
   the grant. If the caller stated a different risk or action, the decision is
   `AUTHORITY_DENIED`. The caller cannot raise either one. Effect and target stay derived from
   the call. A policy with no grant for that caller does not allow the call. On the
   signer/witness path, a bound call with no grant is `AUTHORITY_DENIED` and nothing is sent,
   including when the policy has no `callers` map at all. When `callers` is absent, the kernel
   on its own keeps the old behavior, so `infinityctl evaluate` of an old policy still works.
   `infinityctl evaluate` does not verify tokens. The witness does, so a receipt minted without
   a matching credential is not executed.
3. It recomputes `call_digest` from the call and the verified caller id, using
   `runtime/call_binding.py`.
4. It runs `infinityctl verify-log` on the receipt log (signatures required). If that fails, the
   call is `unauthorized` and is not sent.
5. The receipt must exist and its verdict must be `allow`. A deny, a wait, or a missing id is
   `unauthorized`.
6. The recomputed digest must equal the receipt's `call_digest`, and the receipt's `caller_id`
   must be the verified caller. Anything else, including an unknown call shape, is `mismatch`.
   An allow for caller A cannot be used by caller B: B's token changes the digest and the
   caller id. A mismatch does not use up the allow, so the call that was actually allowed can
   still be run once, with a new token.
7. The allow must be unused. A second attempt with a new token is `reused`. Reusing the same
   token is `IDENTITY_UNVERIFIED`.
8. `issued_at` must be RFC3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`) and not older than `--allow-ttl`
   seconds (default 3600) on the witness clock. Otherwise the call is `late`. A timestamp this
   program cannot parse is `late`.

Only then does it append a signed `started` entry, including the verified caller id. That
entry consumes the allow. Then it performs the call. Then it appends `completed`, or `failed`
if the send raised. One allow, one execution. A failure does not grant a retry. A crash after
`started` leaves the allow consumed; there is no separate `partial` entry. The bare `started`
line is that record. The caller id is part of the entry hash when it is present. Entries that
omit it keep the ids they already had. A new send of a bound call includes it.

Divergence entries (`mismatch`, `unauthorized`, `reused`, `late`, `IDENTITY_UNVERIFIED`,
`AUTHORITY_DENIED`) are signed and chained in the witness log. They do not consume an allow.
A verified token id is spent when the witness accepts the credential, including when the call
is then refused for another reason.

The witness log is a different file from the receipt log, signed with a different key
(`infinityctl witness-append`, `infinityctl witness-verify`). `witness-verify` checks the hash
chain and requires every entry's signature. It does not apply `through` key retirement. A trusted
keys file that uses `through` is refused, so a retirement does not look enforced when it is not.

## What the signer does

When `runtime/ick_service.py` receives `evaluate` with a `call`, it verifies the caller token,
derives `effect` and `target` from the call, computes `call_digest` with the key-file caller id,
sets risk and action from that caller's grant, and puts those on the proposal before the kernel
runs.

- A bad token is `deny` with `IDENTITY_UNVERIFIED`. Nothing is sent.
- If the caller's effect, target, or a supplied `call_digest` disagrees, the decision is `deny`
  with `DESCRIPTION_DISAGREEMENT`. The recorded proposal carries the derived values, so the deny
  describes the call that was sent to the signer.
- If the stated risk or action differs from the grant, or there is no grant, the decision is
  `deny` with `AUTHORITY_DENIED`. The recorded risk and action are the grant's when there is a
  grant. The caller cannot raise either one.
- A shape the registry does not know is `deny` with `UNKNOWN_CALL_SHAPE`, and no digest is kept,
  once the token has verified. A bad token on an unknown shape is still `IDENTITY_UNVERIFIED`.
- If there is no `call`, nothing is derived and no token is required. Effect, target, and any
  digest are the caller's claim, as before.

The kernel does not interpret `call_digest` and does not verify tokens. A non-empty
`payload.binding_fault` is how the signer asks for a description deny. `UNKNOWN_CALL_SHAPE` is
kept as that reason. Any other text is recorded as `DESCRIPTION_DISAGREEMENT`.
`payload.identity_fault` can only deny as `IDENTITY_UNVERIFIED`. `payload.authority_fault` can
only deny as `AUTHORITY_DENIED`. None of those flags can produce an `allow`. When the policy
contains `callers`, the kernel also denies unless `caller_id` is listed, the effect is allowed,
and the target matches a granted prefix, and unless risk and action equal the grant.

`infinityctl evaluate` copies `call_digest` and `caller_id` from the proposal onto the receipt
and hashes each when it is present. It does not derive effect or target and it does not verify
a token. Receipts that omit those fields keep the ids they already had. The witness will not
execute a receipt that has no matching credential.

Known shapes today:

| Shape | Read | Write | Target |
|---|---|---|---|
| `https_request` | GET, HEAD | POST, PUT, PATCH, DELETE | `scheme://host:port/path` and the query if there is one |
| `local_model_tool` | `explain`, `status` | `code`, `wire` | `local-model-tool:{tool}` |

Other methods, other tools, extra fields, IPv6 hosts, and a body given both as text and as
base64 are unknown shapes. The body in the digest is the exact bytes that are sent. Content
encoding is not decoded, chunking is not undone, and a stream cannot be bound. The authorization
header's value is sent to the target but not hashed; only its presence is. Identity is the
verified caller id, which is the second length-prefixed field of both shapes, after the shape
name. `User-Agent` is sent and is not hashed. It names the HTTP library. Hashing it would split
one call into many digests when that library string changes, and it would not authenticate
anyone.

`call_digest` field order, after the prefix `wicket-call/v1\n`, each field a 4-byte big-endian
length and then the bytes:

| Shape | Fields |
|---|---|
| `https_request` | shape, caller id, method (upper), scheme (lower), host (lower), port decimal, path, query, content-type, content-encoding, authorization presence (`1` or `0`, never the value), body bytes |
| `local_model_tool` | shape, caller id, tool name, canonical JSON arguments |

`runtime/call_binding.py` and `verifier/ickverify.py` both use that order. They must agree.
`ickverify` fails a bound call whose allow omits the caller id or whose digest was not computed
with that caller id.

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

`User-Agent` is sent on HTTPS calls and is not part of the digest. It names the HTTP library,
not the caller. Hashing it would split one call into many digests when the library string
changes, and it would not authenticate anyone. The verified caller id is the identity field.
The authorization header's value is sent and not hashed; only its presence was, and identity
is now the caller id. The raw token is not hashed. Risk and action for a granted caller are
taken from the policy. A caller key file the attacker can edit defeats that.

## What this does not prove

- **Observed effect.** A `completed` entry means this process sent the call and received bytes.
  It does not prove the target changed, or that those bytes are what a third party would have
  seen.
- **Account separation.** These tests run the signer and the witness in one process, with two
  keys. They do not probe two operating-system accounts. Caller A versus caller B is two caller
  keys, not two OS users.
- **Whoever can write the caller key file can add callers.** The grant is only as strong as
  that file. There is no key rotation.
- **Observer mode, `state_ref`, retries, heartbeat, `witness-silent`, `unexecuted`.** Not built.
  Absence of a divergence entry does not mean the witness was watching.
- **The clock.** Token expiry and allow expiry use the witness clock. Neither time is proven.
- **A taken-over witness.** Someone who holds the witness key can sign a false execution. The
  split moves trust off Nova. It does not remove it. Witness compromise is not solved here.
- **Egress.** The guarantee holds only when the target cannot be reached except through the
  witness. That restriction is deployment, not code.
- **The local-dev opt-out.** `WICKET_ALLOW_DIRECT_CALLS=1` sends a runtime provider call, or
  a Nova model HTTP call while Nova's policy is unset, with no witness and no derived digest.
  Identity is not required on that path. It warns on stderr on every use and is off by default.
  Any other value is off. It does not let gossip skip an allow, and it does not bypass a Nova
  policy that is already set.
- **A runtime allow with no witness.** `run_turn` can record an allow for its own description
  and then not call the provider. That receipt has no outcome. It is not a send, and it is
  not a derived binding.
- **Direct `infinityctl evaluate`.** It does not verify caller tokens. The witness does.
