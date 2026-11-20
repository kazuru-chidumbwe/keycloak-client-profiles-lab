#!/usr/bin/env bash
# One command for the whole lab: virtual environment, Keycloak, the three states and the trap.
# Usage: ./run.sh [S0 S1 S2L TRAP]   (default: all four)
set -euo pipefail
cd "$(dirname "$0")"
[ -x venv/bin/python ] || { python3 -m venv venv && ./venv/bin/pip install -q -e '.[dev]'; }
bash setup-keycloak.sh
steps=("$@"); [ ${#steps[@]} -gt 0 ] || steps=(S0 S1 S2L TRAP)
for s in "${steps[@]}"; do
  if [ "$s" = TRAP ]; then ./venv/bin/python trap_anyclient.py; else ./venv/bin/python probes.py "$s"; fi
done
