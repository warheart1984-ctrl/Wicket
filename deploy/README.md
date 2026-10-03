# Running it for real: the signer service, Nova and the anchor publisher

These files set up the layout the README's "signer service" section describes, on a Linux server with
systemd: three services under three different accounts, plus the operator screen run by hand by you.

**Read this first.** The point of the separate signer is that a taken-over Nova cannot forge receipts.
That is only true if the accounts and file permissions below are right, and nothing in Python checks
that for you. `deploy/check_setup.py` does (see step 9). These files have been checked as follows, and
no further:

- `systemd-analyze verify` accepts the three units, and `systemd-analyze security` rates them 0.8 to 1.3
  ("SAFE"/"OK") on this machine's systemd 255.
- The exact `ExecStart` command in the signer unit and in the publisher unit is run in the tests, with
  paths swapped for temporary ones, and works: the signer listens with socket mode 660 and stops cleanly
  on SIGTERM; the publisher publishes one anchor to a git repository.
- The audit script is tested against a file layout built with real, different owners and groups, and
  catches 19 deliberate mistakes.
- **They have not been run under a booted systemd with real accounts**, and the publisher has not pushed
  to a hosted git service. Expect to adjust paths for your machine, and watch the first start.

## Try it on a disposable machine first

`deploy/smoke-test.sh` does steps 1 to 9 below on the machine you run it on, using a local git repository
as the anchor repository and Nova's built-in stub model (no network credentials, no API keys), then probes
the separation **as the real users**: Nova cannot read the key, write the log or the policy, or see the
anchor; the publisher cannot write the anchor or use the signer's socket. It leaves a marker file, and
`--cleanup` removes everything it created and refuses to run on a machine without the marker.

```bash
cd infinity-core && cargo build --release      # as yourself
sudo deploy/smoke-test.sh                       # dry run: prints the plan, changes nothing
sudo deploy/smoke-test.sh --apply               # does it
sudo deploy/smoke-test.sh --cleanup             # removes it
```

It creates system accounts and services and listens on 127.0.0.1:18080: use a VM, not a machine you care
about. It is meant to be run by a person and read, and it has **not** been run yet under a booted systemd:
the first run is the test. Run it from your own login with `sudo`, not from a root shell.

## The anchor repository

The publisher pushes one file, `anchor.jsonl`, to a branch named **`anchors`** (not `main`). To read it as
a stranger would, use `git clone -b anchors <url>`. A plain `git clone` of a repository whose default
branch is something else checks out nothing and looks empty. (`--branch` and `--name` change this.)

## The accounts

| Account | What it is | May | May not |
|---|---|---|---|
| `ick-signer` | the signer service | read its key, the policy, the approvals; write the log and anchor | use the network at all |
| `nova` | the governed app (member of `ick-socket`) | reach the signer's socket; read the approvals file; write its own state | read the key, change the policy, write the log or the anchor, approve or deny |
| `ick-publisher` | the anchor publisher (member of `ick-audit`) | read the log and anchor; push to the anchor repository | write the log or anchor; reach the signer's socket; read the signing key |
| *you* (member of `ick-audit`) | the human | read everything; write approvals and denials | |

Groups: `ick-socket` (who may use the signer) and `ick-audit` (who may read what it writes).

## Layout

| Path | Owner : group, mode | Notes |
|---|---|---|
| `/opt/infinity-core` | root | the checkout; `target/release/infinityctl` built here, `venv/` for Nova |
| `/etc/ick/policy.json` | root, 0644 | root-owned so neither the signer nor Nova can change it |
| `/etc/ick/signing.priv` | `ick-signer`, 0600 | the only secret the signer has |
| `/etc/ick/trusted-keys.pub` | root, 0644 | the public key. **Also give a copy to anyone who will verify your logs, by a route that does not go through this server** |
| `/etc/ick/human/` | *you*, 0755 | holds `approvals.jsonl` and `approvals.jsonl.denials`, written only by you |
| `/var/lib/ick/log/` | `ick-signer : ick-audit`, 2750 | `receipts.jsonl` |
| `/var/lib/ick/anchor/` | `ick-signer : ick-audit`, 2750 | `anchor.jsonl` |
| `/run/ick/ick.sock` | `ick-signer : ick-socket`, 0660 | made by the service |
| `/var/lib/nova/` | `nova`, 0750 | `ick-state/` (setgid `ick-audit`) holds pending requests so the operator screen can show them |
| `/etc/ick-publisher/` | `ick-publisher`, 0750 | `deploy_key`, `known_hosts`, `ick-anchor-watch.env` |
| `/var/lib/ick-publisher/status.json` | `ick-publisher : ick-audit` | what the operator screen reads |
| `/etc/nova/nova.env` | root : `nova`, 0640 | provider settings and API keys only |

## Steps

Everything as root unless it says otherwise.

1. **Install the program.**
   ```bash
   git clone https://github.com/YOU/infinity-core /opt/infinity-core && cd /opt/infinity-core
   cargo build --release                       # target/release/infinityctl
   python3 -m venv venv && venv/bin/pip install -e nova-shell
   ```
2. **Create the accounts, groups and directories.**
   ```bash
   install -m 0644 deploy/systemd/sysusers.d/infinity-core.conf /usr/lib/sysusers.d/
   install -m 0644 deploy/systemd/tmpfiles.d/infinity-core.conf /usr/lib/tmpfiles.d/
   systemd-sysusers && systemd-tmpfiles --create
   usermod -aG ick-audit YOUR-LOGIN            # so you can read the log, anchor and pending requests
   chown YOUR-LOGIN /etc/ick/human             # approvals and denials are written here, by you only
   ```
3. **Make the signing key and the policy.**
   ```bash
   cd /etc/ick
   /opt/infinity-core/target/release/infinityctl keygen --out signing.priv --public-out trusted-keys.pub
   chown ick-signer:ick-signer signing.priv && chmod 0600 signing.priv
   install -m 0644 -o root -g root /opt/infinity-core/demo/policy.json policy.json   # or your own
   ```
   Copy `trusted-keys.pub` somewhere that is not this server and tell people it is the key to trust.
4. **Give the publisher its credentials.** Create a separate git repository for the anchor and a deploy
   key that can push to it and nothing else.
   ```bash
   cd /etc/ick-publisher
   ssh-keygen -t ed25519 -N '' -f deploy_key && chown ick-publisher:ick-publisher deploy_key* && chmod 600 deploy_key
   ssh-keyscan github.com > known_hosts && chown ick-publisher:ick-publisher known_hosts
   # check that fingerprint against GitHub's published one before trusting it
   install -m 0600 -o ick-publisher -g ick-publisher /opt/infinity-core/deploy/etc/ick-anchor-watch.env.example ick-anchor-watch.env
   $EDITOR ick-anchor-watch.env                # set ANCHOR_REPO
   ```
   Add `deploy_key.pub` as a deploy key (with write access) on the anchor repository.
5. **Give Nova its provider settings.**
   ```bash
   install -m 0640 -o root -g nova /opt/infinity-core/deploy/etc/nova.env.example /etc/nova/nova.env
   $EDITOR /etc/nova/nova.env
   ```
6. **Install and start the services.**
   ```bash
   install -m 0644 deploy/systemd/ick-signer.service deploy/systemd/ick-anchor-watch.service \
       deploy/systemd/nova-api.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now ick-signer ick-anchor-watch nova-api
   journalctl -u ick-signer -u ick-anchor-watch -u nova-api -n 30
   ```
   No systemd? Run the signer under your supervisor with the same arguments, and use
   `deploy/cron/ick-anchor-publish` (one publish every 5 minutes) instead of the watch service.
7. **Run the operator screen yourself**, in a terminal: `deploy/run-operator.sh`. It prints a link with a
   one-time token. It is not a service on purpose: the token is the only login, and a service would
   write it to the journal.
8. **Make one call and look at the result.**
   ```bash
   curl -s localhost:8080/v1/chat/completions -H 'content-type: application/json' \
        -d '{"model":"x","messages":[{"role":"user","content":"hi"}]}'
   python3 /opt/infinity-core/verifier/ickverify.py /var/lib/ick/log/receipts.jsonl \
        --anchor /var/lib/ick/anchor/anchor.jsonl --trusted-keys /etc/ick/trusted-keys.pub --require-signatures
   ```
9. **Audit the permissions**, now and after every change:
   ```bash
   python3 /opt/infinity-core/deploy/check_setup.py --operator YOUR-LOGIN
   ```
   Every line should be `PASS`. A `FAIL` names the file and who can do what they should not. `SKIP`
   means the file does not exist yet; it is never counted as a pass. The audit reads only ordinary
   owner/group/mode bits. It does not see ACLs, capabilities, SELinux/AppArmor or read-only mounts.

## What the units do

- **`ick-signer.service`**: runs `python -m runtime.ick_service serve …` as `ick-signer`. No network
  (`IPAddressDeny=any`, only Unix sockets), writes only `/var/lib/ick`, no capabilities, a system-call
  filter, `/run/ick` made for it. It removes its socket when stopped.
- **`ick-anchor-watch.service`**: runs `python -m runtime.anchor_git watch …` as `ick-publisher`, which
  checks the log against its own anchor and signatures, pushes the anchor (never force-pushes; refuses an
  anchor that does not continue what is published), and writes `status.json`. It can use the network and
  write only `/var/lib/ick-publisher`. The host key is pinned.
- **`nova-api.service`**: runs `python -m nova.api` as `nova`. Setting `NOVA_ICK_POLICY`,
  `NOVA_ICK_SIGN_KEY` or `NOVA_ICK_BIN` next to `NOVA_ICK_SERVICE` makes Nova refuse to start, and the
  audit fails if `nova.env` names them.

## What this does not give you

- Anyone with root on the machine can undo all of it. Separate accounts defend against a compromised
  *process*, not a compromised *host*.
- Nova and the signer must be on the same machine (it is a Unix socket).
- If the signer is down, Nova refuses every governed call. That is deliberate. There is no failover,
  and `Restart=on-failure` is the only recovery.
- Backups of `/var/lib/ick` and `signing.priv` are yours to arrange. Losing the key stops new signing;
  losing the log loses the history, though a published anchor still shows that it existed.
- Updating the checkout while the services run: restart them afterwards (`systemctl restart …`).
- Key rotation: generate a new key, list **both** public keys in `trusted-keys.pub`, restart the signer
  with the new `signing.priv`. There is no revocation: removing a leaked key from `trusted-keys.pub`
  makes everything it signed fail verification, which is the only lever you have.
