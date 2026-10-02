#!/bin/sh
# Start the operator screen as YOU (the human), not as a service. It prints a one-time token on
# start, and that token is the only login; under systemd it would land in the journal, where other
# accounts may read it. Run this in your own terminal and open the link it prints.
#
# You need to be in the ick-audit group (to read the log, the anchor and Nova's pending requests)
# and to own /etc/ick/human (where your approvals and denials are written).
set -eu
cd "${INFINITY_CORE:-/opt/infinity-core}/nova-shell"
exec "${INFINITY_CORE:-/opt/infinity-core}/venv/bin/python" -m nova.operator_ui \
    --approvals /etc/ick/human/approvals.jsonl \
    --state /var/lib/nova/ick-state \
    --log /var/lib/ick/log/receipts.jsonl \
    --anchor /var/lib/ick/anchor/anchor.jsonl \
    --trusted-keys /etc/ick/trusted-keys.pub --require-signatures \
    --anchor-status /var/lib/ick-publisher/status.json \
    --pending-ttl "${NOVA_ICK_PENDING_TTL:-604800}" \
    --nova-url "http://127.0.0.1:${NOVA_PORT:-8080}" \
    "$@"
