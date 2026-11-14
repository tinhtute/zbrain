# Usage: cargo build -p zbrain && bash docs/audit/2026-11-09/repro/run_all.sh
R=$(cd "$(dirname "$0")" && pwd)
export S=${S:-$(mktemp -d)}
. "$R/env.sh"
for f in "$R"/[0-9][0-9]_*.sh; do echo "===== $(basename "$f")"; timeout 30 bash "$f" 2>&1; done
