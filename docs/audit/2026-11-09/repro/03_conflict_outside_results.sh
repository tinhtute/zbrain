. "$(dirname "$0")/env.sh"
fresh conflict
b=$(printf 'deploy window is tuesday\n' | $Z claim draft --tier projects --title 'Window B' --basis owner | jid); $Z claim approve $b >/dev/null
a=$(printf 'deploy window is friday\n' | $Z claim draft --tier projects --title 'Window A' --basis owner --conflicts-with $b | jid); $Z claim approve $a >/dev/null
$Z reindex >/dev/null
echo "q=deploy window:"; $Z ask deploy window | grep '"status"' | head -1
echo "q=friday:";        $Z ask friday        | grep -E '"status"|"conflicts"' | head -2
