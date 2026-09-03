#!/usr/bin/env bash
# Launcher for the Agentic SOC Analyst.
# Run it from any folder:
#   /Users/peter/GitHub/Multi-Funtion_SOC_Agent_Research/openAI_Agentic_SOC_Analyst/start_button.sh
# or from inside this folder:
#   ./start_button.sh
set -euo pipefail

# Always work from the folder this script lives in, so _keys.py, .venv and
# the session folders are found no matter where it was launched from.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -x .venv/bin/python ]]; then
  echo "Python environment not found: expected $PWD/.venv/bin/python" >&2
  exit 1
fi

# Hand the terminal straight to the app (Ctrl-C and menus behave normally).
exec .venv/bin/python start_button.py "$@"
