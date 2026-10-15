# Handoff notes (for picking this up in a new session)

## About the owner
- Not a coder; learned by asking from first principles. Explain in plain language.
- Merging pull requests is always the owner's job. Open a PR only when asked.
- Wait for BOTH the Linux and Windows CI jobs to be green before the owner merges.

## State of the project
- Project name: **Wicket** (formerly infinity-core). Repo: `warheart1984-ctrl/Wicket`
  (owner name has `1984`; `warheart-ctrl/Wicket` does not exist). The old `infinity-core` URL redirects.
- A new checkout needs no extra repo: clone Wicket, or on an old one run the `set-url` command under
  Owner housekeeping, then `git checkout main && git pull`.
- Everything through PR 35 is merged to `main`.
- Technical names keep the old spelling on purpose: `infinityctl`, the `ick-*` accounts,
  `/opt/infinity-core`, file names, and the signed strings `infinity-core/entry/v1` and
  `infinity-core/anchor/v1` (changing them would invalidate existing signatures and anchors).
- Read `OVERVIEW.md`, then `THREAT_MODEL.md`, then `deploy/README.md`.

## Next planned step
Executor mode is in `docs/executor-mode.md`. It covers dispatched, and the bytes the witness got
back. It does not prove observed effect.

Still open from that design, on purpose:
- Observer mode, `state_ref`, retries after a failure, a witness heartbeat, and a two-account
  probe for the witness. The tests use two keys in one process. Observed effect is not proved.
- `through` key retirement on the witness log. `witness-verify` and `ickverify.py` refuse a key
  file that uses it; they do not apply the cutoff.
- `run_turn` / `python -m runtime` do not call the provider without a witness.
  Nova model HTTP sends nothing unless a policy (`NOVA_ICK_POLICY` or `NOVA_ICK_SERVICE`)
  and a witness are both configured. With both policy variables unset, Nova does not call
  the provider client. `WICKET_ALLOW_DIRECT_CALLS=1` is the local-dev opt-out for the runtime
  and for Nova model HTTP while the policy is unset (stderr warning on every use, off by
  default, no derived digest). It does not apply to gossip.
  Gossip goes through the witness on a derived shape; unknown shapes are denied.
  Observed effect is still not proved.

## Reviewer's attack list
An outside reviewer's six areas (execution gap, identity and authority, time, concurrency, degradation,
human approval load) are in `THREAT_MODEL.md` as untested gaps. The design for the first is
`docs/execution-binding-design.md` (a proposal, not built). The owner plans to send it to the reviewer to
break on paper before it is built. Do not build it until that feedback is in, unless the owner says so.
Keep the reviewer's contact details out of the repo.

## Test counts
Last recorded: Rust 47, root Python 91, `nova-shell` 203 (4 skipped). `main` has gained tests since,
so rerun `cargo test` and `python -m pytest` (root and `nova-shell`) for current numbers.

## Other open items
- The reviewer's other points: actor not authenticated, time not proven correct, concurrency and
  combined effects, behaviour when the signer is down, human approval overload.
- Hosted-git anchor test (needs a private scratch GitHub repo plus a deploy key from the owner).
- Undecided: incremental log verification (faster, weaker check) vs. rotating logs.
- Independent outside review of the threat model and kernel.

## Owner housekeeping
- Linux Mint box still has the smoke-test install: `sudo bash deploy/smoke-test.sh --cleanup`.
- Windows box: run `git remote set-url origin https://github.com/warheart1984-ctrl/Wicket`
  from inside the project folder.
