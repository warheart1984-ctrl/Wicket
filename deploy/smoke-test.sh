#!/usr/bin/env bash
# Install the deploy/ files on THIS machine, start the three services under their real accounts, make
# one governed call, verify the log, and probe the separation as the actual users. Then remove it all.
#
#   sudo deploy/smoke-test.sh              # dry run: print what it would do, change nothing
#   sudo deploy/smoke-test.sh --apply      # do it
#   sudo deploy/smoke-test.sh --cleanup    # remove everything a previous --apply created
#
# Run it from your own login with sudo (not from a root shell): that login becomes the "operator",
# is added to the ick-audit group, and owns /etc/ick/human.
#
# It CREATES: the accounts ick-signer, ick-publisher and nova; the groups ick-socket and ick-audit;
# /opt/infinity-core, /etc/ick, /etc/ick-publisher, /etc/nova, /var/lib/ick, /var/lib/ick-publisher,
# /var/lib/nova; three systemd units; and a marker file, /etc/ick/.smoke-test. It listens on
# 127.0.0.1:18080. It publishes anchors to a LOCAL git repository, never to the network, and uses
# Nova's built-in stub model, so it needs no API keys. A throwaway VM is the right place for it.
# --cleanup refuses to touch a machine that lacks the marker, so it will not delete a real deployment.
#
# Before --apply, build the kernel as yourself:   cargo build --release
set -u

SRC="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX=/opt/infinity-core
PORT=18080
MARKER=/etc/ick/.smoke-test
MODE=dry
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --apply) MODE=apply ;;
    --cleanup) MODE=cleanup ;;
    --force) FORCE=1 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg (see --help)" >&2; exit 2 ;;
  esac
done

PASS=0; FAIL=0
say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf 'PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '      %s\n' "$2"; }
check() { # check "what" cmd...   passes if the command succeeds
  local what="$1"; shift
  local out; if out=$("$@" 2>&1); then ok "$what"; else bad "$what" "$(printf '%s' "$out" | tail -8 | tr '\n' ' ')"; fi
}
refused() { # refused "what" cmd...   passes if the command FAILS (an action that must be impossible)
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then bad "$what" "it succeeded, and it must not"; else ok "$what"; fi
}
die() { printf 'stopped: %s\n' "$1" >&2; exit 2; }

OPERATOR="${SUDO_USER:-}"

plan() {
  cat <<EOF
This would, as root, on this machine:
  1. copy the checkout ($SRC) to $PREFIX and install target/release/infinityctl there
  2. make a Python venv in $PREFIX/venv and install Nova into it
  3. create the accounts ick-signer, ick-publisher, nova and the groups ick-socket, ick-audit
     (systemd-sysusers), the directories (systemd-tmpfiles), and add '${OPERATOR:-<you>}' to ick-audit
  4. generate a signing key, install demo/policy.json as the policy, publish the public key
  5. create a LOCAL bare git repository as the anchor repository (no network, no credentials)
  6. install the three systemd units, start them, and wait for the signer's socket
  7. send one request to Nova on 127.0.0.1:$PORT (stub model) and check it carries a receipt id
  8. wait for the publisher to push the anchor, then verify the log with verifier/ickverify.py,
     with the anchor taken from the published repository and the trusted key
  9. run deploy/check_setup.py
 10. probe the separation as the real users (Nova cannot read the key, write the log or the policy,
     cannot see the anchor; the publisher cannot write the anchor or use the signer's socket)
 11. switch the signing key on the running services: limit the old key to its newest entry in the
     trusted-keys file, install a new key, restart the signer, make another call, and check that the
     whole log still verifies against the published anchor, that a limit placed too early is refused,
     and that an entry added with the OLD key (on a copy of the log) is refused
Nothing has been changed. Run again with --apply to do it, and with --cleanup afterwards to undo it.
EOF
}

preflight() {
  [ "$(id -u)" = 0 ] || die "run this with sudo"
  [ -n "$OPERATOR" ] && [ "$OPERATOR" != root ] || die "run it with sudo from your own login, not from a root shell: that login becomes the operator"
  [ -d /run/systemd/system ] || die "systemd is not running here (this is for a machine booted with systemd)"
  for c in python3 git curl systemctl systemd-sysusers systemd-tmpfiles runuser install tar; do
    command -v "$c" >/dev/null 2>&1 || die "missing command: $c"
  done
  [ -x "$SRC/target/release/infinityctl" ] || die "build the kernel first, as yourself: cd $SRC && cargo build --release"
  python3 -c 'import venv, ensurepip' 2>/dev/null || die "python3 cannot make venvs; on Linux Mint: sudo apt install python3-venv"
  if [ -e /etc/ick ] || id nova >/dev/null 2>&1 || id ick-signer >/dev/null 2>&1; then
    die "this machine already has /etc/ick or one of the accounts. If it is a previous smoke test, run --cleanup first. Nothing was changed."
  fi
  if ss -ltn 2>/dev/null | grep -q ":$PORT "; then die "port $PORT is in use"; fi
}

install_files() {
  say "-- installing"
  mkdir -p "$PREFIX" || return 1
  (cd "$SRC" && tar --exclude=.git --exclude=target --exclude=venv --exclude=__pycache__ --exclude='*.egg-info' \
      --exclude=.pytest_cache -cf - .) | tar -C "$PREFIX" -xf - || return 1
  install -D -m 0755 "$SRC/target/release/infinityctl" "$PREFIX/target/release/infinityctl" || return 1
  chown -R root:root "$PREFIX" && chmod -R go+rX "$PREFIX"
}

make_venv() {
  python3 -m venv "$PREFIX/venv" && "$PREFIX/venv/bin/pip" install -q -e "$PREFIX/nova-shell"
}

accounts() {
  install -m 0644 "$PREFIX/deploy/systemd/sysusers.d/infinity-core.conf" /usr/lib/sysusers.d/ &&
  install -m 0644 "$PREFIX/deploy/systemd/tmpfiles.d/infinity-core.conf" /usr/lib/tmpfiles.d/ &&
  systemd-sysusers && systemd-tmpfiles --create &&
  usermod -aG ick-audit "$OPERATOR" &&
  chown "$OPERATOR" /etc/ick/human &&
  printf 'created by deploy/smoke-test.sh\n' > "$MARKER"
}

keys_and_policy() {
  cd /etc/ick || return 1
  "$PREFIX/target/release/infinityctl" keygen --out signing.priv --public-out trusted-keys.pub >/dev/null &&
  chown ick-signer:ick-signer signing.priv && chmod 0600 signing.priv &&
  chmod 0644 trusted-keys.pub &&
  install -m 0644 -o root -g root "$PREFIX/demo/policy.json" policy.json
}

publisher_setup() {
  git init --bare -q /var/lib/ick-publisher/anchors.git &&
  git --git-dir=/var/lib/ick-publisher/anchors.git symbolic-ref HEAD refs/heads/anchors &&
  chown -R ick-publisher:ick-publisher /var/lib/ick-publisher/anchors.git &&
  printf 'ANCHOR_REPO=/var/lib/ick-publisher/anchors.git\nANCHOR_INTERVAL=20\n' > /etc/ick-publisher/ick-anchor-watch.env &&
  chown ick-publisher:ick-publisher /etc/ick-publisher/ick-anchor-watch.env && chmod 0600 /etc/ick-publisher/ick-anchor-watch.env &&
  printf 'NOVA_PORT=%s\n' "$PORT" > /etc/nova/nova.env &&
  chown root:nova /etc/nova/nova.env && chmod 0640 /etc/nova/nova.env
}

start_services() {
  install -m 0644 "$PREFIX"/deploy/systemd/ick-signer.service "$PREFIX"/deploy/systemd/ick-anchor-watch.service \
      "$PREFIX"/deploy/systemd/nova-api.service /etc/systemd/system/ &&
  systemctl daemon-reload &&
  systemctl start ick-signer ick-anchor-watch nova-api
}

wait_for() { # wait_for seconds cmd...
  local n="$1"; shift
  for _ in $(seq 1 "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

socket_info() {
  python3 - <<'PY'
import json, socket, sys
with socket.socket(socket.AF_UNIX) as c:
    c.settimeout(5); c.connect("/run/ick/ick.sock"); c.sendall(b'{"op":"info"}\n')
    r = json.loads(c.recv(4096)); sys.exit(0 if r.get("ok") else 1)
PY
}

nova_call() {
  local out
  out=$(curl -s -m 20 "http://127.0.0.1:$PORT/v1/chat/completions" -H 'content-type: application/json' \
        -d '{"model":"nova-shell","messages":[{"role":"user","content":"hello"}]}') || return 1
  printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); r=d["nova"]["ick"]["receipt_id"]; print(r); sys.exit(0 if r.startswith("receipt:") else 1)'
}

published() { [ -s /var/lib/ick-publisher/status.json ] && python3 -c '
import json; s=json.load(open("/var/lib/ick-publisher/status.json")); import sys
sys.exit(0 if s.get("consecutive_failures")==0 and s.get("published_records",0)>=1 else 1)'; }

verify_published() {
  # The publisher pushes anchor.jsonl to the branch "anchors". Read it from there, as a stranger would.
  local tmp; tmp=$(mktemp -d) || return 1
  local repo=/var/lib/ick-publisher/anchors.git
  if ! git --git-dir="$repo" rev-parse --verify -q refs/heads/anchors >/dev/null 2>&1; then
    echo "the anchor repository has no 'anchors' branch; branches: $(git --git-dir="$repo" branch --list | tr '\n' ' ')"
    rm -rf "$tmp"; return 1
  fi
  if ! git --git-dir="$repo" show anchors:anchor.jsonl > "$tmp/anchor.jsonl" 2>"$tmp/err"; then
    echo "cannot read anchor.jsonl from the anchors branch: $(cat "$tmp/err")"
    rm -rf "$tmp"; return 1
  fi
  local out rc
  out=$(python3 "$PREFIX/verifier/ickverify.py" /var/lib/ick/log/receipts.jsonl --anchor "$tmp/anchor.jsonl" \
      --trusted-keys /etc/ick/trusted-keys.pub --require-signatures 2>&1); rc=$?
  printf '%s\n' "$out" | grep -E '^(VERIFIED|NOT VERIFIED|  problem:|  note:)'
  rm -rf "$tmp"; return $rc
}

# ---- the key switch -------------------------------------------------------------------------------------
# Retire the signing key at its newest entry, install a new one, and check that the log still verifies
# across the hand-over, and that a stolen old key cannot add trusted entries afterwards. These helpers only
# touch the files they are given, so they can be tried without the services.

ctl() { printf '%s' "${CTL:-$PREFIX/target/release/infinityctl}"; }

receipt_at() { # receipt_at LOG first|last : the receipt id of the first or last entry
  python3 - "$1" "$2" <<'PY'
import json, sys
rows = [l for l in open(sys.argv[1], encoding="utf-8").read().splitlines() if l.strip()]
print(json.loads(rows[0 if sys.argv[2] == "first" else -1])["receipt_id"])
PY
}

write_limited_trust() { # write_limited_trust OUT OLD_KEY_LINE RECEIPT NEW_KEY_LINE : old key believed only through RECEIPT
  printf '%s through %s\n%s\n' "$2" "$3" "$4" > "$1"
}

write_unlimited_trust() { # write_unlimited_trust OUT OLD_KEY_LINE NEW_KEY_LINE
  printf '%s\n%s\n' "$2" "$3" > "$1"
}

verify_files() { # verify_files LOG ANCHOR KEYS : the standalone verifier, signatures required
  local out rc
  out=$(python3 "${VERIFIER:-$PREFIX/verifier/ickverify.py}" "$1" --anchor "$2" --trusted-keys "$3" --require-signatures 2>&1); rc=$?
  printf '%s\n' "$out" | grep -E '^(VERIFIED|NOT VERIFIED|  problem:)'
  return $rc
}

forge_with_key() { # forge_with_key PRIV POLICY LOG ANCHOR : append one genuinely signed entry to (a COPY of) a log
  local tmp pid; tmp=$(mktemp) || return 1
  pid=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["policy_id"])' "$2") || return 1
  cat > "$tmp" <<JSON
{"version":"infinity.proposal.v1","proposal_id":"forged-by-thief","actor":{"kind":"agent","id":"thief"},"action":"get_status","target":"demo","effect":"read","risk":"low","requires_human_approval":false,"policy_version":"$pid","payload":{},"evidence_refs":[]}
JSON
  "$(ctl)" evaluate --proposal "$tmp" --policy "$2" --log "$3" --anchor "$4" --sign-key "$1" >/dev/null
  local rc=$?; rm -f "$tmp"; return $rc
}

published_matches_live() { # the published anchor is the same as the live one
  local tmp; tmp=$(mktemp -d) || return 1
  git --git-dir=/var/lib/ick-publisher/anchors.git show anchors:anchor.jsonl > "$tmp/p" 2>/dev/null &&
  cmp -s "$tmp/p" /var/lib/ick/anchor/anchor.jsonl
  local rc=$?; rm -rf "$tmp"; return $rc
}

two_keys_signed_everything() { # every entry is signed, by exactly two different keys
  python3 - /var/lib/ick/log/receipts.jsonl <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8").read().splitlines() if l.strip()]
keys = {r.get("key_id") for r in rows}
assert all(r.get("signature") for r in rows), "an entry is unsigned"
assert len(keys) == 2, f"expected two signing keys, found {len(keys)}"
PY
}

ks_prepare() { # remember what is needed, make the new key
  receipt_at /var/lib/ick/log/receipts.jsonl last  > "$WORK/limit" &&
  receipt_at /var/lib/ick/log/receipts.jsonl first > "$WORK/first" &&
  cp /etc/ick/signing.priv "$WORK/old.priv" && cp /etc/ick/trusted-keys.pub "$WORK/old.pub" &&
  "$(ctl)" keygen --out "$WORK/new.priv" --public-out "$WORK/new.pub" >/dev/null &&
  chmod 600 "$WORK/old.priv" "$WORK/new.priv"
}

ks_switch() { # old key limited to its newest entry in the trusted file; new key installed; signer restarted
  write_limited_trust "$WORK/trusted.new" "$(head -n1 "$WORK/old.pub")" "$(cat "$WORK/limit")" "$(head -n1 "$WORK/new.pub")" &&
  install -m 0644 -o root -g root "$WORK/trusted.new" /etc/ick/trusted-keys.pub &&
  install -m 0600 -o ick-signer -g ick-signer "$WORK/new.priv" /etc/ick/signing.priv &&
  systemctl restart ick-signer
}

ks_too_early_refused() {
  write_limited_trust "$WORK/early" "$(head -n1 "$WORK/old.pub")" "$(cat "$WORK/first")" "$(head -n1 "$WORK/new.pub")" &&
  ! verify_files /var/lib/ick/log/receipts.jsonl /var/lib/ick/anchor/anchor.jsonl "$WORK/early"
}

ks_thief() { # a copy of the log gets an entry signed by the OLD key: refused with the limit, accepted without it
  cp /var/lib/ick/log/receipts.jsonl "$WORK/thief.log" && cp /var/lib/ick/anchor/anchor.jsonl "$WORK/thief.anchor" &&
  forge_with_key "$WORK/old.priv" /etc/ick/policy.json "$WORK/thief.log" "$WORK/thief.anchor" &&
  write_unlimited_trust "$WORK/unlimited" "$(head -n1 "$WORK/old.pub")" "$(head -n1 "$WORK/new.pub")" &&
  verify_files "$WORK/thief.log" "$WORK/thief.anchor" "$WORK/unlimited" >/dev/null &&
  ! verify_files "$WORK/thief.log" "$WORK/thief.anchor" /etc/ick/trusted-keys.pub
}

key_switch() {
  say "-- switching the signing key on the running services"
  WORK=$(mktemp -d) || { bad "a private work directory"; return; }
  chmod 700 "$WORK"
  check "the old key's newest entry is noted and a new key made"          ks_prepare
  check "old key limited to that entry, new key installed, signer restarted" ks_switch
  check "the signer is back and answers"                                  wait_for 20 socket_info
  check "ick-signer is active"                                            systemctl is-active --quiet ick-signer
  check "Nova still answers, and the reply carries a receipt id"          nova_call
  say "-- waiting for the publisher (every 20 s)"
  check "the publisher pushed the new anchor"                             wait_for 90 published_matches_live
  check "the whole log verifies across the switch, against the PUBLISHED anchor, signatures required" verify_published
  check "every entry is signed, by exactly two keys"                      two_keys_signed_everything
  check "a limit placed too early is refused (the entries after it fail)" ks_too_early_refused
  check "an entry added with the OLD key is refused, and would be accepted without the limit" ks_thief
  check "the permission audit still passes"                               python3 "$PREFIX/deploy/check_setup.py" --operator "$OPERATOR" --nova-env /etc/nova/nova.env
  check "ick-anchor-watch is still active"                                systemctl is-active --quiet ick-anchor-watch
  rm -rf "$WORK"
}

probes() {
  refused "Nova cannot read the signing key" runuser -u nova -- cat /etc/ick/signing.priv
  refused "Nova cannot append to the receipt log" runuser -u nova -- sh -c 'echo x >> /var/lib/ick/log/receipts.jsonl'
  refused "Nova cannot list the anchor directory" runuser -u nova -- ls /var/lib/ick/anchor
  refused "Nova cannot change the policy" runuser -u nova -- sh -c 'echo x >> /etc/ick/policy.json'
  refused "Nova cannot create an approvals file" runuser -u nova -- sh -c 'echo x > /etc/ick/human/approvals.jsonl'
  refused "the publisher cannot write the anchor" runuser -u ick-publisher -- sh -c 'echo x >> /var/lib/ick/anchor/anchor.jsonl'
  refused "the publisher cannot write the log" runuser -u ick-publisher -- sh -c 'echo x >> /var/lib/ick/log/receipts.jsonl'
  refused "the publisher cannot read the signing key" runuser -u ick-publisher -- cat /etc/ick/signing.priv
  refused "the publisher cannot use the signer's socket" runuser -u ick-publisher -- python3 -c '
import socket; c=socket.socket(socket.AF_UNIX); c.connect("/run/ick/ick.sock")'
  check "Nova can use the signer's socket" runuser -u nova -- python3 -c '
import socket; c=socket.socket(socket.AF_UNIX); c.connect("/run/ick/ick.sock")'
  check "the publisher can read the log and the anchor" runuser -u ick-publisher -- sh -c \
      'head -c1 /var/lib/ick/log/receipts.jsonl >/dev/null && head -c1 /var/lib/ick/anchor/anchor.jsonl >/dev/null'
}

apply() {
  preflight
  say "Installing. This changes the machine; --cleanup undoes it."
  check "files copied to $PREFIX"                      install_files
  check "Nova installed into a venv"                   make_venv
  check "accounts, groups and directories created"     accounts
  check "signing key and policy in /etc/ick"           keys_and_policy
  check "local anchor repository and settings"         publisher_setup
  check "services started"                             start_services
  check "the signer is listening and answers"          wait_for 20 socket_info
  check "ick-signer is active"                         systemctl is-active --quiet ick-signer
  check "ick-anchor-watch is active"                   systemctl is-active --quiet ick-anchor-watch
  check "nova-api is active"                           wait_for 30 systemctl is-active --quiet nova-api
  say "-- one governed call"
  if wait_for 30 curl -s -m 3 "http://127.0.0.1:$PORT/health"; then :; else sleep 3; fi
  check "Nova answers and the reply carries a receipt id"  nova_call
  say "-- waiting for the publisher (every 20 s)"
  check "the publisher pushed the anchor"              wait_for 90 published
  check "the log verifies with the standalone verifier, against the PUBLISHED anchor, signatures required" verify_published
  check "the permission audit passes"                  python3 "$PREFIX/deploy/check_setup.py" --operator "$OPERATOR" --nova-env /etc/nova/nova.env
  say "-- the separation, probed as the real users"
  probes
  key_switch
  summary
}

summary() {
  say ""
  say "$PASS passed, $FAIL failed."
  if [ "$FAIL" -gt 0 ]; then
    say "Look at:  journalctl -u ick-signer -u ick-anchor-watch -u nova-api -n 60 --no-pager"
    say "and send the whole output of this script back."
  else
    say "Next: log out and in (so your new ick-audit group applies), then run $PREFIX/deploy/run-operator.sh"
    say "and open the link it prints. Remove everything with:  sudo $0 --cleanup"
  fi
  [ "$FAIL" -eq 0 ]
}

cleanup() {
  [ "$(id -u)" = 0 ] || die "run this with sudo"
  if [ ! -f "$MARKER" ] && [ "$FORCE" != 1 ]; then
    die "$MARKER is missing: this machine was not set up by this script, so nothing was removed. (--force overrides; only if you are sure.)"
  fi
  say "Removing the smoke-test installation..."
  systemctl stop nova-api ick-anchor-watch ick-signer 2>/dev/null
  systemctl disable nova-api ick-anchor-watch ick-signer 2>/dev/null
  rm -f /etc/systemd/system/ick-signer.service /etc/systemd/system/ick-anchor-watch.service /etc/systemd/system/nova-api.service
  systemctl daemon-reload
  rm -rf /etc/ick /etc/ick-publisher /etc/nova /var/lib/ick /var/lib/ick-publisher /var/lib/nova /run/ick "$PREFIX"
  rm -f /usr/lib/sysusers.d/infinity-core.conf /usr/lib/tmpfiles.d/infinity-core.conf
  for u in nova ick-publisher ick-signer; do id "$u" >/dev/null 2>&1 && userdel "$u" 2>/dev/null; done
  for g in ick-socket ick-audit; do getent group "$g" >/dev/null 2>&1 && groupdel "$g" 2>/dev/null; done
  say "Done. (Your own login keeps working; it was only added to the ick-audit group, which no longer exists.)"
}

[ "${SMOKE_SOURCE_ONLY:-}" = 1 ] && return 0 2>/dev/null

case "$MODE" in
  dry) plan ;;
  apply) apply ;;
  cleanup) cleanup ;;
esac
