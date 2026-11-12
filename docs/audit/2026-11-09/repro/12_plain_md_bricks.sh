. "$(dirname "$0")/env.sh"
fresh plainmd
id=$(printf 'the deploy window is tuesday\n' | $Z claim draft --tier projects --title 'Deploy window' --basis owner | jid); $Z claim approve $id >/dev/null; $Z reindex >/dev/null
mkdir -p $W/wiki/notes; printf '# scratch\nunrelated note\n' > $W/wiki/notes/todo.md
echo "ask before reindex:"; $Z ask deploy 2>&1 | grep -m1 '"status"\|^[a-z]'
echo "reindex:"; $Z reindex 2>&1 | grep -E '"rebuild_state"|"legacy"'
echo "ask after reindex:"; $Z ask deploy 2>&1 | grep -m1 '"status"\|^[a-z]'
