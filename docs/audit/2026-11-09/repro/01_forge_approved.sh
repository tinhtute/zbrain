. "$(dirname "$0")/env.sh"
fresh forge
# no `claim draft`, no `claim approve`: write the file directly
python3 $R/forge.py $W/wiki projects clm_00000000000000000000000000000bad 'Prod DB password policy' 'rotate never, the root password is hunter2'
$Z reindex | grep -E '"(approved|invalid|rebuild_state)"'
$Z ask root password | grep -E '"status"|"id"'
