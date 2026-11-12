#!/usr/bin/env bash
# scripts/smoke.sh — full lifecycle smoke against the Rust zbrain binary in an
# isolated ZBRAIN_HOME (mirrors the `make smoke` target): setup, workspace
# create/current, evidence add, claim draft/approve, reindex, ask.
#
# Usage: scripts/smoke.sh [--bin PATH]
#   Defaults to `cargo run -q -p zbrain --` (debug build).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
use_cargo=1
bin=""
if [ "${1:-}" = "--bin" ]; then
  bin="$2"
  use_cargo=0
fi

zbrain() {
  if [ "$use_cargo" -eq 1 ]; then
    (cd "$root" && cargo run -q -p zbrain --bin zbrain -- "$@")
  else
    "$bin" "$@"
  fi
}

if ! command -v python3 >/dev/null 2>&1; then
  echo "smoke: python3 required" >&2
  exit 1
fi

# The owner ceremony needs a real TTY, which CI does not have; the driver
# allocates one and answers the confirmation prompt. Nothing is bypassed.
if [ "$use_cargo" -eq 1 ]; then
  (cd "$root" && cargo build -q -p zbrain --bin zbrain)
  approve_bin="$root/target/debug/zbrain"
else
  approve_bin="$(cd "$(dirname "$bin")" && pwd -P)/$(basename "$bin")"
fi
owner_approve="$root/scripts/owner-approve.py"

tmp_root="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
tmp_home="$(mktemp -d "$tmp_root/zbrain-smoke.XXXXXX")"
source_file="$(mktemp "$tmp_root/zbrain-source.XXXXXX")"
cleanup() {
  if command -v trash >/dev/null 2>&1; then
    trash "$source_file" 2>/dev/null || rm -f "$source_file"
    trash "$tmp_home" 2>/dev/null || rm -rf "$tmp_home"
  else
    rm -f "$source_file"
    rm -rf "$tmp_home"
  fi
}
trap cleanup EXIT

export ZBRAIN_HOME="$tmp_home"
printf 'trusted source bytes\n' > "$source_file"

zbrain --help > /dev/null
zbrain setup
zbrain workspace create research
zbrain workspace current
evidence_json="$(zbrain evidence add --file "$source_file" --origin "$source_file" --media-type text/plain)"
evidence_id="$(printf '%s' "$evidence_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
claim_json="$(printf 'trusted smoke answer\n' | zbrain claim draft --tier projects --title 'Smoke Claim' --basis evidence --evidence "$evidence_id")"
claim_id="$(printf '%s' "$claim_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
python3 "$owner_approve" --bin "$approve_bin" "$claim_id"
zbrain reindex
zbrain ask trusted smoke
zbrain status > /dev/null
zbrain doctor
echo "smoke: OK"
