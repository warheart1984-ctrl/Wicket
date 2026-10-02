# infinity-core: overview

**What it is.** A gateway between people and AI models in which every model call must first be
approved by a small, deterministic *kernel*, and every decision leaves a *receipt* that is hard
to alter without being noticed. A person can approve held-back requests from a simple screen.

## How a request flows

```
client ──► Nova API ──► ICK kernel ──► allow ──► model provider (Groq, NVIDIA, OpenRouter, …)
(app, tool)  :8080        │  judges one               │
                          │  proposal                 ▼
                          ├─► deny ───────────► 403   reply + the kernel's receipt id
                          └─► await ──► 403 + hash ──► pending list     │
                                                                         ▼
                                    after the call: an *outcome* entry (completed / failed,
                                    hashes of the request and reply, never their text)
                                                          │
 human ──► operator screen / CLI ── approve (one request, expires, limited uses) ──┘
                                      (a separate process; the Nova API cannot approve)

every decision and outcome ──► receipt log, if one is configured (each entry names the one before it,
                                and carries the time it was issued, which the hash covers)
                    ──► anchor file (log length + latest receipt id)
                    ──► copied to a separate git repo, so deleting the newest receipts is caught
```

## The pieces

| Piece | What it does | Lives in |
|---|---|---|
| **Signer service** (optional) | Runs the kernel, policy, key and log under another account; Nova asks over a Unix socket and holds none of them. | `runtime/ick_service.py` |
| **ICK kernel** (Rust) | Judges a proposal: `allow`, `deny` or `await_human_approval`, and issues a hash-linked receipt, optionally signed with an Ed25519 key. Never calls a model. | `crates/`, `contracts/` |
| **Receipt chain, outcomes, anchor** | Each entry includes the previous one's id, so editing one breaks the rest. After a model call an *outcome* entry is chained in, pointing at the `allow` that permitted it. The anchor records the log's length and head, which also catches deleted *newest* entries. | kernel CLI (`--log`, `--anchor`, `record-outcome`) |
| **Nova shell** (Python) | The model-facing API (OpenAI-style) and CLI. Asks the kernel before every model call when `NOVA_ICK_POLICY` is set; fails closed if the kernel is missing. | `nova-shell/` |
| **Human approvals** | A held request is parked with a hash; a person approves or denies that exact request (approval: expiry, use limit; denial: final); undecided requests expire after 7 days. The kernel's answer is always final. | `nova-shell/nova/ick_approvals.py` |
| **Operator screen** | Pending requests with Approve and Deny buttons, log status, recent receipts. Localhost only, token-protected, strict CSP. | `nova-shell/nova/operator_ui.py` |
| **Anchor publisher** | `publish` / `verify` against a separate git repo; never force-pushes. | `runtime/anchor_git.py` |
| **Small chat runtime** | A minimal governed chat loop (Groq, NVIDIA, OpenRouter) used to prove the kernel end to end. | `runtime/` |

## What you can rely on, and what you cannot

- **Kernel first, or no call.** Covered paths: every provider route, streaming, the node tool that calls
  a local model, node gossip. Not covered: a model called from outside Nova.
- **Tampering is noticed.** Edited or removed entries break the chain, including the time each was
  issued. Deleted newest entries are caught by the anchor, and by the *published* anchor even if the
  attacker edits both local files.
- **Every model call leaves a matching pair.** The decision (`allow`) and its outcome (`completed` or
  `failed`, with SHA-256 hashes of the request and reply). The verifier rejects an outcome that answers
  a deny, a pending request, a missing receipt, or an `allow` that already has one, and it counts allows
  with no outcome. If the outcome cannot be written, the reply is withheld ("no evidence, no answer"),
  except for streams, whose text has already been sent: there the gap shows up as an allow with no outcome.
- **Signatures are optional, and only as good as the key and where you check them.** With `--sign-key`
  every receipt, outcome and anchor record is Ed25519-signed, so forging history needs the private key and
  not just write access to the files (shown live: a log with every hash recomputed passes the hash check and
  fails the signature check). Verification must use public keys kept where the log's writer cannot change
  them, with `--require-signatures` on, or someone who strips every signature goes unnoticed. Signing does
  **not** stop a rollback to an earlier genuine state (the published anchor does), and the key is a file on
  the writing machine, so a compromised writer can sign forgeries. Times come from that machine's clock.
  Old (v1) receipts are still accepted but their time was never covered by the hash.
- **Approvals bind to one request.** Not reusable for a different request, expire, and are used up.
- **Trust assumptions (these are yours to set up):**
  the approvals file must be writable only by the human operator, not by the Nova server;
  the anchor repository must be outside the log writer's control;
  the gate is **opt-in** (off unless `NOVA_ICK_POLICY` is set);
  the operator token is the only login; someone who can edit Nova's code can bypass the gate.

## Try it

```bash
cargo build
cd nova-shell && pip install -e . pytest PyYAML httpx && python -m pytest   # 203 pass, 4 skipped
NOVA_ICK_POLICY=../demo/policy.json NOVA_PROVIDER=external \
NOVA_EXTERNAL_URL=https://integrate.api.nvidia.com/v1 NOVA_EXTERNAL_API_KEY=... \
NOVA_EXTERNAL_MODEL=nvidia/nemotron-3-super-120b-a12b python -m nova.api
```
Full instructions, settings and limits for each piece are in `README.md`.

## State of verification

Tests: Rust 47, root Python 91, `nova-shell` 203 (+4 skipped). For the security-relevant rules, each
guard was removed in turn and a test failed. Run live against real Groq, NVIDIA and OpenRouter models:
allow, deny, human approval, chained and anchored log, the operator screen in a real Chromium.

**Not done / not verified:** publishing to a *hosted* git repo (tested with a local one); the
local-model tool against a real Ollama or vLLM (tested with fakes); Windows file locking for the last use of an
approval, and the key-file permission check (Unix only);
the anchor publisher can run on a schedule (`watch`) and the operator screen shows how stale it is, but nothing starts it for you, it must run as a different user than Nova with push credentials Nova lacks, and it is untested against a hosted git service; the signing key can live in a separate signer service under another account (`runtime/ick_service.py`), but it is still a file (no key store or
hardware key); no revocation or "valid until" for keys; the older proposal, policy and decision contracts
still list required fields only (the receipt, outcome and anchor formats are strict). One full-suite failure was
seen once and could not be reproduced in about 30 later runs (cause unknown).

## Where it came from

Kernel from `infinity-runtime`; the Nova shell from `Project-Infinity1/lawful-nova-shell` (Python
core only; desktop app, installers and packaging left out; one change to its code: a `User-Agent`
header, which Groq requires). Everything else is new. The large Python AAIS application in
`infinity` / `project-infinity` was **not** brought over.

## How it was built

Eleven pull requests, each building on the one before:
#1 kernel · #2 chat runtime · #3 receipt chaining · #4 log anchor · #5 Nova shell · #6 Nova asks the
kernel · #7 gate the remaining paths · #8 human approvals · #9 anchor publisher · #10 `/v1/chat`
fix · #11 operator screen. After that: real timestamps covered by the hash (receipt v2) and outcome
records, which this overview now describes. A fresh build of `main` passes the tests listed above.
