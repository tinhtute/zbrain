# Repro env: R = this dir, S = scratch (override with S=...), Z = zbrain binary (override with Z=...).
R=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
S=${S:-$(mktemp -d)}
Z=${Z:-$(git -C "$R" rev-parse --show-toplevel)/target/debug/zbrain}
fresh() { export ZBRAIN_HOME=$S/homes/$1; if [ -e "$ZBRAIN_HOME" ]; then trash "$ZBRAIN_HOME"; fi; mkdir -p $S/homes; $Z setup >/dev/null; $Z workspace create ws >/dev/null; W=$ZBRAIN_HOME/workspaces/ws; }
jid() { python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'; }
