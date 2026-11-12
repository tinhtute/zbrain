. "$(dirname "$0")/env.sh"
fresh symlink
id=$(printf 'the deploy window is tuesday\n' | $Z claim draft --tier projects --title 'Deploy window' --basis owner | jid); approve $id >/dev/null
mkdir -p $S/outside; mv $W/wiki/projects/$id.md $S/outside/$id.md; ln -s $S/outside/$id.md $W/wiki/projects/$id.md
$Z reindex 2>&1 | grep -E '"approved"|"rebuild_state"|"error"|^[a-z]'
$Z ask deploy 2>&1 | grep -m1 '"status"\|^[a-z]'
