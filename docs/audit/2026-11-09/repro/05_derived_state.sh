. "$(dirname "$0")/env.sh"
fresh derived
id=$(printf 'the deploy window is tuesday\n' | $Z claim draft --tier projects --title 'Deploy window' --basis owner | jid); approve $id >/dev/null; $Z reindex >/dev/null
cat $W/.zbrain/generation.json; echo
echo "-- drop indexes/ only"; trash $ZBRAIN_HOME/indexes; $Z ask deploy 2>&1 | head -1; $Z reindex >/dev/null 2>&1; $Z ask deploy 2>&1 | grep -m1 '"status"'
echo "-- drop workspace .zbrain/ (generation + lock)"; trash $W/.zbrain; $Z ask deploy 2>&1 | grep -m1 '"status"\|index'; $Z reindex >/dev/null 2>&1; $Z ask deploy 2>&1 | grep -m1 '"status"'
echo "-- drop both"; trash $W/.zbrain $ZBRAIN_HOME/indexes; $Z reindex >/dev/null 2>&1; $Z ask deploy 2>&1 | grep -m1 '"status"'
