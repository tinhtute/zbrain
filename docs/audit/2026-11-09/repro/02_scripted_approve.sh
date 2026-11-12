. "$(dirname "$0")/env.sh"
fresh scripted
# agent-style: no TTY on stdin/stdout/stderr, no challenge, no grant
id=$(printf 'agent wrote this\n' | $Z claim draft --tier projects --title 'Agent fact' --basis owner | jid)
$Z claim approve $id </dev/null 2>&1 | cat | grep '"status"'
