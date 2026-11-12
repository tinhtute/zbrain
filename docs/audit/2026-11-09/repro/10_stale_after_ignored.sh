. "$(dirname "$0")/env.sh"
fresh stale
id=$(printf 'on-call is alice\n' | $Z claim draft --tier projects --title 'On-call' --basis owner | jid)
# stale_after has no CLI flag; set it on the draft, then go through the normal approve
sed -i 's/^status: draft/status: draft\nstale_after: "2020-01-01T00:00:00Z"/' $W/wiki/projects/$id.md
$Z claim approve $id >/dev/null; $Z reindex >/dev/null
echo "plain ask:";            $Z ask on-call | grep -m1 '"status"'
echo "ask --as-of now:";      $Z ask --as-of $(date -u +%Y-%m-%dT%H:%M:%SZ) on-call | grep -m1 '"status"'
echo "doctor:"; $Z doctor 2>&1 | grep -i stale | head -2
