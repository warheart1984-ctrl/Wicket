# infinity-core

> New here? Start with [OVERVIEW.md](OVERVIEW.md): one page on what this is, how a request flows, and what to trust.

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

GitHub Actions (`.github/workflows/ci.yml`) runs these, the build and both Python suites on Linux and
Windows for every push and pull request, plus the browser test for the operator screen on Linux. The
Python suites skip kernel tests quietly when `infinityctl` has not been built, so the workflow checks that
both packages can find it. Some tests are skipped on Windows because what they check does not exist there
(Unix key-file modes, signals sent to a child, `#!` stand-in binaries, Unix sockets for the signer service).

## Governed chat runtime

`runtime/` is a small standard-library Python package. Each chat turn is turned into
a proposal and sent to the kernel first. The model is called only if the kernel says
`allow`; the receipt is appended to a log. Message text is never put in the proposal.

```bash
cargo build
GROQ_API_KEY=... python -m runtime "What is the capital of France?" --provider groq
python -m pytest        # offline tests, no keys needed (169 pass)
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

### Timestamps (receipt v2)

Every entry records when it was issued (RFC 3339 UTC), and from receipt `v2` on the time is part
of the hash, so editing it is detected. The command-line tool uses the current UTC time unless you
pass `--issued-at`; the kernel library takes the time as an argument and stays deterministic. The
time comes from the writing machine's clock: the hash makes a change *detectable*, it does not prove
the clock was right. Old `v1` receipts still verify, but their time was never covered by the hash
and they carried the placeholder `demo-provenance`.

### Outcome records

A decision says a call was *allowed*. An outcome says what *happened*. After a model call,
`infinityctl record-outcome --log LOG --decision-receipt <id> --status completed|failed
[--request-sha256 H] [--response-sha256 H]` appends an entry to the same chain. It holds SHA-256
hashes of the request and the reply, never their text.

`verify-log` rejects an outcome that does not answer an earlier `allow`, or answers one that
already has an outcome, so "a model was called" always points at the decision that permitted it. It
also reports `N allowed without an outcome`: calls still running, never finished, or whose outcome could
not be written. The Nova gate and the small runtime record an outcome after every call; if it cannot be
written the reply is withheld (for a stream, whose text is already out, the gap is reported instead).
The typed contracts are `contracts/receipt.v2.json` and `contracts/outcome.v1.json`.

### Contracts for the kernel's input and output

`contracts/proposal.v1.json`, `policy.v1.json` and `decision.v1.json` are now strict JSON Schemas like the
receipt ones: every field is typed, unknown fields are refused, hashes and the verdict are pattern/enum
checked, and ids and names cannot be empty. Tests check the real thing against them: every fixture, the
sample policy, what the runtime and Nova build, and the kernel's actual decisions for all three verdicts.

- **The kernel is deliberately more lenient than the contracts.** It ignores unknown fields and answers a wrong
  version, an unknown effect or risk, or a mismatched policy id with a logged `deny` (`fixtures/deny-unknown-
  contract-version.v1.json` is exactly that: the contract rejects it, the kernel must deny it). So a proposal
  that fails the contract is safe to submit; it is just not well formed. The kernel itself does not run the
  schemas.
- `effect` and `risk` are plain non-empty strings in the proposal contract, with the known values described
  in the schema, because the kernel treats an unknown one as a denial, not a malformed request.
- `payload` must be an object (the kernel accepts any JSON), and `reason_codes` in a decision are upper-case
  codes rather than a closed list, so a new code does not break old validators.
- The schema tests need the `jsonschema` package and skip without it.

### Signed receipts

Receipts, outcomes **and anchor records** can carry an Ed25519 signature, so forging or editing
history needs a secret key and not just write access to the files.

```bash
infinityctl keygen --out signing.priv --public-out signing.pub   # private key created 0600; never overwrites
infinityctl evaluate ... --log LOG --anchor A --sign-key signing.priv   # or set INFINITY_SIGN_KEY / NOVA_ICK_SIGN_KEY
infinityctl verify-log --log LOG --anchor A --trusted-keys signing.pub --require-signatures
```

- **What is signed.** The entry's id (a hash of every other field, including the time), behind a prefix
  that names the purpose, so a signature for an entry cannot be reused for an anchor record or the
  reverse. Signatures are optional: unsigned entries and old logs verify exactly as before.
- **Checking.** `--trusted-keys` is a file of `ed25519-public:<hex>` lines (blank lines and `#` comments
  allowed). Keep it where the log's writer cannot change it: a key found inside the log proves nothing.
  Without `--trusted-keys`, signatures are not looked at; with it but without `--require-signatures`, a log
  that carries no signatures at all passes and says so ("authenticity is NOT checked"). Use
  `--require-signatures` once signing is on, otherwise someone who strips every signature goes unnoticed.
  Once an entry is signed, every later one must be, so stripping only the newest signatures is always caught.
- **Key hygiene.** The tool refuses a private key file that other users can read (`chmod 600`), refuses to
  overwrite on `keygen`, never prints the private key, and will not append an unsigned entry to a signed
  log. A log can move to a new key: list both public keys in the trusted-keys file.
- **The operator screen** shows `signatures verified`, `NOT AUTHENTICATED: no signatures` or
  `signatures: not checked`, and takes `--trusted-keys` / `--require-signatures`. The anchor publisher takes
  the same two options.

**What signing does not do.**
- It does **not** stop a rollback: removing the newest entries *and* their anchor records leaves an earlier
  state in which every signature is genuine. Catching that needs the copy of the newest anchor that was
  published to the separate git repository, which is why the two are meant to be used together (a test shows
  the local check passing and the published check failing).
- The private key is a file on the machine that writes the log. Anyone who can read it, which includes the
  Nova process and its user, can sign forgeries. Signing protects against tampering with *stored* files
  (backups, other accounts, a copied repository), not against a compromised writer. The signer service
  below fixes that, if you run it as another account.
- Signatures prove who wrote an entry, not that the clock was right.

Typed contracts: `contracts/receipt.v2.json`, `contracts/outcome.v1.json` and `contracts/anchor.v1.json`
(the latter two now allow the optional `key_id` and `signature`). The kernel gains one dependency,
`ed25519-dalek`; the command-line tool gains `getrandom` for key generation.

### Checking a log without trusting us: the standalone verifier

```bash
python verifier/ickverify.py receipts.jsonl --anchor anchor.jsonl --trusted-keys signing.pub --require-signatures
```

`verifier/ickverify.py` is one file with no dependencies beyond Python's standard library. It does not
call `infinityctl`: it recomputes every hash and verifies every Ed25519 signature itself (with the same
strictness as the kernel's `verify_strict`), so someone checking a log does not have to trust the Rust
binary, Nova, or this repository's other code. Exit status is 0 verified, 1 not verified, 2 unreadable
input; `--json` prints a report. It prints, every time, what a pass does and does not show, and notes
anything it could not check (no anchor, no keys, unanchored newest entries, allows with no outcome).

- **Tested against the Rust verifier**, not just by itself: real signed and anchored logs, about 40
  kinds of deliberate damage under six combinations of anchor, keys and `--require-signatures`, correctly
  hashed logs whose *meaning* is wrong (a second outcome for one allow, an outcome for a denial), random
  single-character damage, awkward text such as `U+2028` in hashed fields, and the RFC 8032 test vector.
  That testing found a real bug in the verifier on the way: it split lines with Python's `splitlines()`,
  which also splits on `U+2028`, so a valid log containing that character was misread. It now splits on
  newlines only, like the kernel. The verifier's checks were also broken one at a time to confirm a test
  fails each time.
- **It is a second implementation by the same author**, not an independent audit.
- **It differs from the Rust checker in one deliberate way:** it refuses a public key whose encoding is
  not canonical, which the Rust decoder would accept. It also warns about fields in an entry that the
  hash does not cover; the kernel accepts those silently.
- The anchor and the trusted keys must come from somewhere the log's writer cannot edit. The point of
  `THREAT_MODEL.md` is the list of what a passing check still does not mean.

### Keeping the key out of Nova: the signer service

With the steps above, Nova runs `infinityctl` itself, so Nova's account can read the key. The signer
service moves the kernel, the policy, the key and the log into a different process under a different
account. Nova asks it over a Unix socket and gets the decision and receipt back.

```bash
# as the service account (its own user; the key, policy, approvals file and log directory are its alone)
python -m runtime.ick_service serve --socket /run/ick/ick.sock --policy policy.json \
    --log /var/lib/ick/receipts.jsonl --anchor /var/lib/ick-anchor/anchor.jsonl \
    --sign-key /etc/ick/signing.priv --approvals /etc/ick/approvals.jsonl --allow-uid <nova's uid>

# as Nova (no policy, key or binary in its environment: setting any of them next to this is refused)
NOVA_ICK_SERVICE=/run/ick/ick.sock python -m nova.api
```

- **Why the service runs the kernel instead of just signing.** A service that signed whatever Nova sent
  would let a taken-over Nova sign forgeries. Here the verdict is computed with the service's own
  policy, so Nova cannot make a receipt say `allow` when the policy says otherwise, cannot choose the
  policy, and cannot edit the log. A test runs the service and a Nova stand-in as two real accounts and
  checks that the second can get receipts signed but cannot read the key or write the log or policy.
- **Approvals are checked there too.** An approval id reaches the kernel only if it is in the
  human-written approvals file, is bound to *this* request's hash (`infinityctl proposal-hash`), has not
  expired and has not been denied. Nova cannot invent one. Counting uses is still done by Nova alone, so
  a taken-over Nova can replay an approval that still has uses left, until it expires.
- **Who may connect.** The socket's file mode (`--socket-mode`, default 660, set before it is bound) is the
  gate; `--allow-uid` adds a check of the connecting process's uid (Linux). Requests are limited to 1 MiB
  and 15 s. A stale socket file is replaced; a live one is never taken over.
- **The operator screen and verification** read the log and anchor files as before (read-only is enough),
  so those must be readable by their accounts. Keep the anchor where Nova cannot write it, and publish
  it (see above).
- **Fail closed.** If the service is down, slow or answers with anything unexpected, the call is refused
  (`KERNEL_UNAVAILABLE`); if only the outcome cannot be recorded, the reply is withheld as before.

**What it does not do.**
- It cannot tell whether Nova describes its action truthfully. A taken-over Nova can ask about a harmless
  read and then do something else; the log proves what was asked and what the policy said, not what was
  done. Outcomes ("completed", the hashes) are Nova's claim, now signed and chained.
- Nova can still stop asking, or stop the service from being reachable. Rollback and silence are caught by
  the published anchor and `watch`, not by the signature.
- The key is still a file, on the service's machine. There is no hardware key or key store, and no
  revocation or "valid until" for keys.
- Nothing starts or supervises the service for you (use systemd or similar), and Nova and the service must
  be on the same machine (it is a Unix socket).
- Running it as root, or as the same user as Nova, gives none of this. The test only proves the separation
  when the two really are different accounts.

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

#### Publishing on a schedule

The anchor only protects what it has already published, so publishing has to happen regularly and,
just as important, you have to be able to tell when it has stopped.

```bash
python -m runtime.anchor_git watch --anchor A.jsonl --repo <git url> --status-file publish-status.json \
    --interval 300 [--log LOG --trusted-keys KEYS --require-signatures]
```

- Publishes every `--interval` seconds (default 300) and stops cleanly on Ctrl+C or SIGTERM. A failed
  publish (network, credentials) is retried after a growing delay: it doubles each time, up to
  `--max-backoff` (default: 1800 seconds, or the interval if that is longer). The loop never exits
  because of an error; being stale or failing is how a problem is noticed.
- A **refusal** (the log does not match its anchor, or the local anchor does not continue what was
  published) is a different thing. It is reported as `INTEGRITY REFUSAL (needs a person, not a retry)`,
  flagged in the status file, and not retried any faster. It may mean tampering.
- `--status-file` records each attempt: when it last succeeded, how many records are published, the
  failures in a row, the last error (one line, URL credentials hidden), and whether the last refusal was an
  integrity refusal. It never contains the repository URL. It is written atomically. The one-shot
  `publish` takes `--status-file` too, so a cron job feeds the same display.
- The **operator screen** (`--anchor-status FILE`, `--anchor-stale-after SECONDS`, default 900) shows
  `anchor published 41s ago`, how many entries are **not yet published** (a rollback of those would go
  unnoticed), `anchor publishing failing (N in a row)`, `ANCHOR PUBLISH REFUSED (possible tampering)`, or
  `anchor has never been published`. Set the stale threshold to a few times your interval.

Ways to run it (nothing starts it for you):

```cron
# one-shot every 5 minutes; also records its status
*/5 * * * *  /opt/infinity/venv/bin/python -m runtime.anchor_git publish --anchor /var/lib/infinity/a.jsonl \
             --repo git@anchors.example:org/anchors.git --status-file /var/lib/anchor-publisher/status.json
```

```ini
# /etc/systemd/system/anchor-publisher.service
[Service]
User=anchor-publisher
ExecStart=/opt/infinity/venv/bin/python -m runtime.anchor_git watch --anchor /var/lib/infinity/a.jsonl \
          --repo git@anchors.example:org/anchors.git --status-file /var/lib/anchor-publisher/status.json
Restart=always
```

**Where to run it matters more than how.** Run the publisher as a *different user (or machine)* than
Nova. It needs read access to the log and anchor, and push access to the anchor repository, and **Nova
must not have those push credentials**. If the process that writes the log can also push, anyone who
compromises it can rewrite the published history too, and the whole mechanism protects nothing.
Likewise the status file is written by the publisher, so the operator screen shows what the publisher
*says*; the real check is `python -m runtime.anchor_git verify`, run from somewhere independent.

Limits: protection is only as recent as the last successful publish (the screen counts the entries since),
and the interval is the window in which a rollback could go unnoticed. A publisher host that is itself
compromised can fake a healthy status. Not covered by tests: a hosted git service (tested with a local
repository).

## Nova shell

`nova-shell/` is the Python core of the lawful Nova shell, brought over from
`Project-Infinity1/lawful-nova-shell`: a CLI (`python -m nova.cli`) and an
OpenAI-style HTTP API (`python -m nova.api`, port 8080) that attaches a governance
receipt to every reply. Left out: the Electron desktop app, OS installers, quickstart
and packaging scripts.

```bash
cd nova-shell
pip install -e .          # fastapi, pydantic, uvicorn (tests also need pytest, PyYAML, httpx)
python -m pytest          # 210 pass, 4 skipped (the skips test parts that were left out)
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
receipt log) and `NOVA_ICK_ANCHOR` (needs the log). To keep the key and log away from Nova entirely, set
`NOVA_ICK_SERVICE` instead (see the signer service).

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
- `/v1/chat` (Nova's "lawful brain" route) works with `NOVA_PROVIDER=external` as well as
  `ollama`, and takes its settings from the same place as the other routes, including
  the `NOVA_CONFIG` file. It used to answer 500 for anything but Ollama. Failures from
  the model come back as a JSON error, not a bare 500. It is gated once per call.
- Not gated, on purpose: `/v1/chat` with no provider set (or `NOVA_PROVIDER=local`). It uses the built-in stub,
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
python -m nova.cli deny <proposal_hash> --by alice --reason "not this"
```

1. A refused request comes back as HTTP 403 `KERNEL_AWAITING_APPROVAL`, with its
   `proposal_hash` and an `approve_with` hint. Nova also lists it as pending.
2. `approve` shows what is being approved and asks for confirmation (`--yes` skips the
   prompt, and is required when not run from a terminal). It records one approval bound
   to that hash, with an expiry (default 3600 s) and a use limit (default 1).
3. When the same request comes in again, Nova finds the approval, passes it to the kernel,
   and records the use. Whatever the kernel answers is final: Nova never overrides it.
   Both the wait and the approved call are in the receipt log.
4. `deny` is the other answer. It records a denial in `<approvals file>.denials`, which Nova reads
   the same way it reads approvals and must not be able to write. A denial is final for that exact
   request: it cancels any approval already given for it, nothing can approve it afterwards, and
   Nova answers it with HTTP 403 `KERNEL_DENIED_BY_HUMAN`. A request that differs at all has a new
   hash and starts over as pending. There is no undo command; a human removes the denial's line
   from the file. A denials file that exists but cannot be read counts as denying everything,
   and a lost or corrupted line would fail open, so keep the file where only the human can write.
5. A request nobody decides expires after `NOVA_ICK_PENDING_TTL` seconds (default 604800, 7 days; a
   missing, zero, negative or unparseable value means the default, never "forever"). An expired
   request disappears from the lists and can no longer be approved or denied; nothing is deleted
   from the file. If the same request is asked for again it comes back as a new pending one.
   Approvals keep their own expiry and denials stay final. The operator screen needs the same
   value (`--pending-ttl` or the same env var) or it will disagree with Nova about what is
   expired; it shows how many requests expired undecided.

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

### Operator screen

A small web page for the human who runs the system. It shows what Nova is waiting on
(with Approve and Deny buttons), whether the receipt log still verifies against its anchor, the
most recent receipts, and whether Nova is up. It works on a phone-sized screen and in dark mode.

```bash
cd nova-shell
python -m nova.operator_ui --approvals <approvals file> --state <state dir> \
                           --log <receipt log> --anchor <anchor file> [--nova-url http://127.0.0.1:8080]
# prints:  Operator screen: http://127.0.0.1:8765/#token=...   <- open exactly that link
```

The settings default to the same `NOVA_ICK_*` variables Nova uses. `--anchor-repo <git url>`
(or `NOVA_ANCHOR_REPO`) adds a button that checks the log against the published anchor.

**It is a separate process from the Nova API, on purpose.** Nova's API still has no route for
approving, and a test checks that. Run the operator screen as the human operator's account, and
keep the approvals file where the Nova server cannot write it. How the screen is locked down:
- It listens on loopback only and refuses any other address.
- Every data and action request needs a random token, printed once at startup. The token is
  carried in the URL *fragment* (never sent to a server, so not in logs or Referer headers) and
  removed from the address bar after sign-in.
- The `Host` header must be its own loopback address (blocks DNS rebinding) and an `Origin`
  header, when sent, must match (blocks other websites). No cross-origin access is granted.
- A strict Content-Security-Policy with a fresh nonce on every page load. Data reaches the page as
  JSON and is written with `textContent`, so hostile text (a request's target, say) is shown as
  plain text and never runs. This was checked in a real Chromium.
- The server enforces the same limits as the CLI plus its own: 1 minute to 24 hours, 1 to 100
  uses, and a request must already be pending. It can write approval and denial records and nothing else.

**Limits.** The token is the only login: anyone who can read your terminal output or your
browser can approve or deny. There is no HTTPS (it never leaves the machine). The page refreshes every few seconds.
Browser tests need Node with Playwright and Chromium and are skipped when those are missing.

## Planned

Nothing is queued right now.
