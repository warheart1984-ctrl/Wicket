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
python -m pytest        # offline tests, no keys needed
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

## Nova shell

`nova-shell/` is the Python core of the lawful Nova shell, brought over from
`Project-Infinity1/lawful-nova-shell`: a CLI (`python -m nova.cli`) and an
OpenAI-style HTTP API (`python -m nova.api`, port 8080) that attaches a governance
receipt to every reply. Left out: the Electron desktop app, OS installers, quickstart
and packaging scripts.

```bash
cd nova-shell
pip install -e .          # fastapi, pydantic, uvicorn (tests also need pytest, PyYAML, httpx)
python -m pytest          # 55 pass, 4 skipped (the skips test parts that were left out)
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

Nova's receipts and the ICK kernel's receipts are **separate systems** for now. Nova
does not yet ask the kernel before it calls a model.

## Planned

1. Make Nova ask the ICK kernel before it calls a model, so there is one set of receipts.
2. A helper that copies the latest anchor to an external place (a separate git repo).
3. A minimal operator surface.
