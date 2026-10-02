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

## Planned

1. A helper that copies the latest anchor to an external place (a separate git repo).
2. A minimal operator surface.
