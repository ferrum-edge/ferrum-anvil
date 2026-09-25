#!/usr/bin/env bash
# Vertical slice (plan §3): real gateway + controlled backend → saved request →
# failure analysis → export → import into a clean profile (different key, no
# shared keychain) → repeat successfully. Requires `anvil-lab up core` running.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
anvil="$root/target/debug/anvil"
work="${1:-$(mktemp -d)}"
rm -rf "$work"; mkdir -p "$work"
export ANVIL_PASSPHRASE='slice-passphrase-1'
export ANVIL_EXPORT_PASSPHRASE='slice-export-passphrase'
A() { "$anvil" --data-dir "$work/machine-a" "$@"; }
B() { "$anvil" --data-dir "$work/machine-b" "$@"; }
step() { printf '\n=== %s\n' "$*"; }

step "machine A: create profile, workspace, nested folders, saved requests"
A profile create alice | sed 's/RECOVERY KEY.*/RECOVERY KEY (withheld from log)/'
A workspace create Payments >/dev/null
A add Payments "Healthy echo" --folder "Gateway/Smoke" --url http://127.0.0.1:18080/ok/echo >/dev/null
A add Payments "Backend refused" --folder "Gateway/Faults" --url http://127.0.0.1:18080/up/refused/ >/dev/null
A workspace tree Payments

step "machine A: send through the real gateway (trusted Ferrum profile over lab HTTP)"
A send "Gateway/Smoke/Healthy echo" --workspace Payments --trust-ferrum 127.0.0.1 && echo "exit=0"

step "machine A: deliberately broken backend — expect a cautious gateway diagnosis"
set +e; A send "Gateway/Faults/Backend refused" --workspace Payments; code=$?; set -e
echo "exit=$code (1 = transport/application failure, as expected)"

step "machine A: full encrypted backup"
A export --mode backup --out "$work/alice.anvil-backup"

step "machine B (clean install, new key): dry-run then import"
B profile create bob | sed 's/RECOVERY KEY.*/RECOVERY KEY (withheld from log)/'
B import "$work/alice.anvil-backup" --dry-run | head -20
B import "$work/alice.anvil-backup" >/dev/null && echo "imported"
B workspace tree Payments

step "machine B: repeat the sends"
B send "Gateway/Smoke/Healthy echo" --workspace Payments && echo "exit=0"
set +e; B send "Gateway/Faults/Backend refused" --workspace Payments >/dev/null; echo "exit=$? (fault still diagnosed on machine B)"; set -e
echo; echo "vertical slice completed in $work"
