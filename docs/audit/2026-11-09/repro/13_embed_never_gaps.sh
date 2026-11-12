. "$(dirname "$0")/env.sh"
fresh embed
id=$(printf 'the deploy window is tuesday\n' | $Z claim draft --tier projects --title 'Deploy window' --basis owner | jid); approve $id >/dev/null
$Z reindex --embed | grep -A3 '"embedding"' | tr -d '\n '; echo
q='quantum chromodynamics lattice'
echo "lexical: $($Z ask "$q" | grep -m1 '"status"')"
echo "--embed: $($Z ask --embed "$q" | grep -m1 '"status"')  -> $($Z ask --embed "$q" | grep -m1 '"title"')"
