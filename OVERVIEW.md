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
                          └─► await ──► 403 + hash ──► pending list
                                                          │
 human ──► operator screen / CLI ── approve (one request, expires, limited uses) ──┘
                                      (a separate process; the Nova API cannot approve)

every decision ──► receipt log, if one is configured (each receipt names the one before it)
                    ──► anchor file (log length + latest receipt id)
                    ──► copied to a separate git repo, so deleting the newest receipts is caught
```

## The pieces

| Piece | What it does | Lives in |
|---|---|---|
| **ICK kernel** (Rust) | Judges a proposal: `allow`, `deny` or `await_human_approval`, and signs a receipt. Never calls a model. | `crates/`, `contracts/` |
| **Receipt chain + anchor** | Each receipt includes the previous one's id, so editing one breaks the rest. The anchor records the log's length and head, which also catches deleted *newest* receipts. | kernel CLI (`--log`, `--anchor`) |
| **Nova shell** (Python) | The model-facing API (OpenAI-style) and CLI. Asks the kernel before every model call when `NOVA_ICK_POLICY` is set; fails closed if the kernel is missing. | `nova-shell/` |
| **Human approvals** | A held request is parked with a hash; a person approves that exact request (expiry, use limit). The kernel's answer is always final. | `nova-shell/nova/ick_approvals.py` |
| **Operator screen** | Pending requests with an Approve button, log status, recent receipts. Localhost only, token-protected, strict CSP. | `nova-shell/nova/operator_ui.py` |
| **Anchor publisher** | `publish` / `verify` against a separate git repo; never force-pushes. | `runtime/anchor_git.py` |
| **Small chat runtime** | A minimal governed chat loop (Groq, NVIDIA, OpenRouter) used to prove the kernel end to end. | `runtime/` |

## What you can rely on, and what you cannot

- **Kernel first, or no call.** Covered paths: every provider route, streaming, the node tool that calls
  a local model, node gossip. Not covered: a model called from outside Nova.
- **Tampering is noticed.** Edited or removed receipts break the chain. Deleted newest receipts are
  caught by the anchor, and by the *published* anchor even if the attacker edits both local files.
- **Approvals bind to one request.** Not reusable for a different request, expire, and are used up.
- **Trust assumptions (these are yours to set up):**
  the approvals file must be writable only by the human operator, not by the Nova server;
  the anchor repository must be outside the log writer's control;
  the gate is **opt-in** (off unless `NOVA_ICK_POLICY` is set);
  the operator token is the only login; someone who can edit Nova's code can bypass the gate.

## Try it

```bash
cargo build
cd nova-shell && pip install -e . pytest PyYAML httpx && python -m pytest   # 128 pass, 4 skipped
NOVA_ICK_POLICY=../demo/policy.json NOVA_PROVIDER=external \
NOVA_EXTERNAL_URL=https://integrate.api.nvidia.com/v1 NOVA_EXTERNAL_API_KEY=... \
NOVA_EXTERNAL_MODEL=nvidia/nemotron-3-super-120b-a12b python -m nova.api
```
Full instructions, settings and limits for each piece are in `README.md`.

## State of verification

Tests: Rust 9, root Python 23, `nova-shell` 128 (+4 skipped). For the security-relevant rules, each
guard was removed in turn and a test failed. Run live against real Groq, NVIDIA and OpenRouter models:
allow, deny, human approval, chained and anchored log, the operator screen in a real Chromium.

**Not done / not verified:** publishing to a *hosted* git repo (tested with a local one); the
local-model tool against a real Ollama or vLLM (tested with fakes); Windows file locking for the last use of an
approval; no Deny button yet; anchors are published by hand, not on a schedule. One full-suite failure
was seen once and could not be reproduced in about 30 later runs (cause unknown).

## Where it came from

Kernel from `infinity-runtime`; the Nova shell from `Project-Infinity1/lawful-nova-shell` (Python
core only; desktop app, installers and packaging left out; one change to its code: a `User-Agent`
header, which Groq requires). Everything else is new. The large Python AAIS application in
`infinity` / `project-infinity` was **not** brought over.

## The 11 branches, in merge order (each builds on the one before)

`bootstrap-ick` → `runtime-chat` → `receipt-chaining` → `log-anchor` → `nova-shell` →
`nova-asks-kernel` → `gate-remaining-paths` → `nova-approvals` → `anchor-git-helper` →
`fix-v1-chat-external` → `operator-surface`
