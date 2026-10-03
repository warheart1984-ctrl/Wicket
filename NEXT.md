# Handoff notes (for picking this up in a new session)

## About the owner
- Not a coder; learned by asking from first principles. Explain in plain language.
- Merging pull requests is always the owner's job. Open a PR only when asked.
- Wait for BOTH the Linux and Windows CI jobs to be green before the owner merges.

## State of the project
- Project name: **Wicket** (formerly infinity-core). Repo: `warheart1984-ctrl/Wicket`.
- Everything through PR 35 is merged to `main`.
- Technical names keep the old spelling on purpose: `infinityctl`, the `ick-*` accounts,
  `/opt/infinity-core`, file names, and the signed strings `infinity-core/entry/v1` and
  `infinity-core/anchor/v1` (changing them would invalidate existing signatures and anchors).
- Read `OVERVIEW.md`, then `THREAT_MODEL.md`, then `deploy/README.md`.

## Next planned step (from an outside review)
The reviewer's main point: a valid receipt proves what was asked and what the policy said, not
that the action actually executed was the one authorized. Planned work:
1. Add a section to `THREAT_MODEL.md` separating five things: proposed, authorized, dispatched,
   executed, observed. State which Wicket proves today (the first two) and which it does not.
2. Add an independent execution witness: a component Nova does not control that checks the
   actual call against the authorized proposal's hash and records a signed "divergence" entry on
   mismatch. Test it with the attack: get a receipt for a harmless read, do something else.

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
