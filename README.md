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

## Planned

1. A small Python chat runtime with Groq, NVIDIA and OpenRouter providers.
2. Every action the runtime wants to take goes through the kernel first.
3. A minimal operator surface.
