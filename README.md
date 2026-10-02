# infinity-core

A fresh start that combines the best parts of the Infinity projects.

## What is here

- **`crates/infinity-kernel`** — ICK, a deterministic governance kernel. It judges
  agent-proposed actions and returns an `allow`, `deny` or `await` receipt. It does
  not call providers, tools or cloud services. Taken from `infinity-runtime`.
- **`crates/infinity-cli`** — command-line front end for the kernel.
- **`contracts/`, `fixtures/`, `demo/`** — the JSON contracts, test cases and sample policy.

## Checks

```bash
cargo fmt --check
cargo clippy --tests -- -D warnings
cargo test
```

## Governed chat runtime

`runtime/` is a small standard-library Python package. Each chat turn is turned into
a proposal and sent to the kernel first. The model is called only if the kernel says
`allow`; the receipt is appended to a log. Message text is never put in the proposal.

```bash
cargo build
GROQ_API_KEY=... python -m runtime "What is the capital of France?" --provider groq
python -m pytest        # offline tests, no keys needed (23 pass)
```

Providers: `groq`, `nvidia`, `openrouter` (keys in `GROQ_API_KEY`, `NVIDIA_API_KEY`,
`OPENROUTER_API_KEY`; models can be overridden with `INFINITY_<NAME>_MODEL`).
All three were checked live. Reasoning models get a 256-token minimum and a
no-thinking or low-reasoning setting so short replies are not left empty.

## Receipt chaining

`infinityctl evaluate --log FILE` locks the log, checks that the existing chain is
intact, then appends a receipt linked to the previous one. `infinityctl verify-log
--log FILE` (or `Kernel.verify()` in Python) checks the whole chain. If the log has
been edited, the runtime refuses to take another turn and calls no provider.

What the chain alone catches: an edited receipt, or one removed from the start or
middle. What it does **not** catch: receipts deleted from the **end**, because nothing
records how long the log should be.

## Log anchor

An anchor closes that gap. With `--anchor FILE`, every turn also appends a record of
the log's length and latest receipt id to a separate file. From then on:

- `infinityctl verify-log --log LOG --anchor FILE` fails if the log is shorter than an
  anchor ("receipts were deleted") or if the receipt at an anchored position changed
  ("the log was rewritten").
- `infinityctl evaluate --log LOG --anchor FILE` refuses to append to a log that fails
  that check, so a truncated log cannot quietly be continued.
- In Python, `Kernel(receipt_log=..., anchor=...)` does the same, and a refused turn
  calls no provider. CLI: `python -m runtime "hi" --receipts LOG --anchor FILE`.

**The anchor is only as strong as where you keep it.** If whoever can edit the receipt
log can also edit the anchor file, nothing is gained. Keep it on another machine or
account, in an append-only store, or in a separate repository you commit to. The
runtime cannot do this for you, so `--anchor` is opt-in and has no default location.
An attacker who can edit both files can still erase history; the anchor raises the
bar, it is not a proof.

### Publishing the anchor to a separate git repository

`runtime/anchor_git.py` puts the anchor where the log's writer cannot quietly rewrite it:

```bash
# on a schedule (cron, a timer): push the anchor, checking the log against it first
python -m runtime.anchor_git publish --anchor A.jsonl --repo <git url> --log LOG

# any time, from anywhere: check a log against the PUBLISHED anchor only
python -m runtime.anchor_git verify --log LOG --repo <git url>
```

- `publish` never force-pushes. It refuses if the local anchor is not a pure continuation
  of what is already published (so an edited, shortened or replaced anchor is caught), and
  with `--log` it refuses if the log fails its own anchor. Each publish is one commit.
- `verify` uses only the published copy. This is what catches the attack the local check
  misses: delete the newest receipts **and** edit the local anchor to match.
- Only a count and a receipt hash per record are published, never message text.

**Limits.** It only helps if the repository is outside the log writer's control (another
account, or a branch where force-pushes and deletions are blocked). Receipts added since the
last `publish` are not covered until the next one. Authentication is whatever git already
has. Tested against a local git repository, not against a hosted one yet.

## Nova shell

`nova-shell/` is the Python core of the lawful Nova shell, brought over from
`Project-Infinity1/lawful-nova-shell`: a CLI (`python -m nova.cli`) and an
OpenAI-style HTTP API (`python -m nova.api`, port 8080) that attaches a governance
receipt to every reply. Left out: the Electron desktop app, OS installers, quickstart
and packaging scripts.

```bash
cd nova-shell
pip install -e .          # fastapi, pydantic, uvicorn (tests also need pytest, PyYAML, httpx)
python -m pytest          # 97 pass, 4 skipped (the skips test parts that were left out)
python -m nova.api        # default provider is a built-in rule-based stub, not an LLM
```

To use a real model, point its external provider at any OpenAI-compatible host:

```bash
NOVA_PROVIDER=external NOVA_EXTERNAL_URL=https://integrate.api.nvidia.com/v1 \
NOVA_EXTERNAL_API_KEY=... NOVA_EXTERNAL_MODEL=nvidia/nemotron-3-super-120b-a12b \
python -m nova.api
```

Groq (`https://api.groq.com/openai/v1`, `openai/gpt-oss-120b`) works the same way. Both
were checked live. One change was made to the imported code: a `User-Agent` header,
because Groq rejects Python's default one.

### Nova asks the kernel first

Set `NOVA_ICK_POLICY` to a policy file and Nova asks the ICK kernel before it calls a
model; with it unset nothing changes. Optional: `NOVA_ICK_BIN`, `NOVA_ICK_LOG` (chained
receipt log) and `NOVA_ICK_ANCHOR` (needs the log).

```bash
cargo build
NOVA_ICK_POLICY=demo/policy.json NOVA_ICK_LOG=.runtime/receipts.jsonl \
NOVA_PROVIDER=external NOVA_EXTERNAL_URL=https://integrate.api.nvidia.com/v1 \
NOVA_EXTERNAL_API_KEY=... NOVA_EXTERNAL_MODEL=nvidia/nemotron-3-super-120b-a12b \
python -m nova.api
```

- An `allow` verdict lets the call through, and the reply carries `nova.ick` with the
  kernel's verdict and receipt id.
- `deny` or `await_human_approval` stops the call before any model is contacted and
  returns HTTP 403 with `KERNEL_DENIED` or `KERNEL_AWAITING_APPROVAL`.
- It **fails closed**: a missing `infinityctl` or any kernel error also stops the call
  (`KERNEL_UNAVAILABLE`). It never silently allows.
- Only message counts and sizes go to the kernel, never the text.
- Covered, with tests that fail if the gate is removed:
  - every route that calls a provider: `/v1/chat/completions` (including streaming),
    `/v1/completions`, `/node/submit` and `/node/replay`;
  - the Ollama path behind `/v1/chat` (the async `invoke` call);
  - the node's local-model tool (`/node/tool`: code, wire, explain), checked once per
    call, which covers both the Ollama attempt and the vLLM fallback;
  - node gossip to peers (`gossip_to_peers`), checked once per peer as a `write`. A peer
    that is refused shows `status: "refused"` in the results and nothing is sent.
- Any refusal on any route becomes HTTP 403 through one app-wide handler, never a 500.
- Gossip is a `write`, and the demo policy requires approval for writes, so with
  `demo/policy.json` gossip waits until a human approves it (see below), or until you use
  a policy with `effects_requiring_approval: []`.
- Not gated, on purpose: `/v1/chat` with no provider set. It uses the built-in stub,
  which contacts nothing (a test proves that, with the network blocked).
- Not checked: nothing in `nova/` runs shell commands or opens raw sockets, but a model
  called from outside Nova is not gated. The local-model tool was checked with fakes, not
  against a real Ollama or vLLM server.
### Human approvals

When the kernel says `await_human_approval`, a person can clear that one request. Set
`NOVA_ICK_APPROVALS` (the approvals file) and optionally `NOVA_ICK_STATE` (a folder Nova
writes to; default `.runtime/ick-state`):

```bash
python -m nova.cli approvals                      # what is waiting
python -m nova.cli approve <proposal_hash> --by alice --expires-in 600 --uses 1
```

1. A refused request comes back as HTTP 403 `KERNEL_AWAITING_APPROVAL`, with its
   `proposal_hash` and an `approve_with` hint. Nova also lists it as pending.
2. `approve` shows what is being approved and asks for confirmation (`--yes` skips the
   prompt, and is required when not run from a terminal). It records one approval bound
   to that hash, with an expiry (default 3600 s) and a use limit (default 1).
3. When the same request comes in again, Nova finds the approval, passes it to the kernel,
   and records the use. Whatever the kernel answers is final: Nova never overrides it.
   Both the wait and the approved call are in the receipt log.

Identical requests give identical hashes (the proposal is built from the request's
content, hashed, never its text). An approval for one prompt does not cover another, and
an approval for one gossip peer does not cover another peer.

**Where the trust boundary is.** The kernel only checks that an approval id is in the list
it is given, so it cannot tell a human from Nova. These rules come from Nova, not the kernel:
- There is **no HTTP route for approving**, on purpose, and a test checks it. Anything that
  could call one would be approving its own requests.
- Nova only **reads** the approvals file. Keep it where the Nova server cannot write
  (another account, a read-only mount, file permissions). If Nova can write it, nothing
  stops it approving itself.
- This protects against requests arriving over the API or from model-driven tools. It does
  not protect against someone who can edit Nova's code or the approvals file.
- On Windows, simultaneous use of the last approval is not locked (POSIX file locks only),
  so two concurrent calls could both use it.
- A gossip round to the same peer has the same hash each time, so one approval covers
  one round unless you raise `--uses`.

- Nova keeps its own receipts too. The two systems now sit side by side, with the
  kernel's receipt id included in Nova's reply. They are not merged into one log.

## Planned

1. Make `/v1/chat` work with the external provider (it only supports Ollama today).
2. Publish the anchor automatically (on a timer, or every N turns) instead of by hand.
3. A minimal operator surface.
