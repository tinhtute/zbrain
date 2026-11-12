# Repro env: R = this dir, S = scratch (override with S=...), Z = zbrain binary (override with Z=...).
R=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
S=${S:-$(mktemp -d)}
ROOT=$(cd "$R/../../../.." && pwd)
Z=${Z:-$ROOT/target/debug/zbrain}
fresh() { export ZBRAIN_HOME=$S/homes/$1; if [ -e "$ZBRAIN_HOME" ]; then trash "$ZBRAIN_HOME"; fi; mkdir -p $S/homes; $Z setup >/dev/null; $Z workspace create ws >/dev/null; W=$ZBRAIN_HOME/workspaces/ws; }
jid() { python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'; }
# `claim approve` needs the owner ceremony (a TTY); the driver allocates one and
# answers the confirmation prompt. Nothing is bypassed, and stderr is dropped so
# repro output stays comparable to the pre-gate baseline.
approve() { python3 "$ROOT/scripts/owner-approve.py" --bin "$Z" "$@" 2>/dev/null; }
# Portable helpers (macOS + Linux): BSD sed -i needs a suffix arg and macOS has no `timeout`.
subst() { perl -pi -e "$1" "$2"; }   # usage: subst 's/a/b/' file
if ! command -v timeout >/dev/null 2>&1; then
  if command -v gtimeout >/dev/null 2>&1; then timeout() { gtimeout "$@"; }
  else timeout() { local s=$1; shift; perl -e 'alarm shift; exec @ARGV or die "$!"' "$s" "$@"; }; fi
fi
