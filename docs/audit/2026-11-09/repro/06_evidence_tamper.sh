. "$(dirname "$0")/env.sh"
fresh evid
printf 'vendor SLA is 99.9%%\n' > $S/src.txt
e=$($Z evidence add --file $S/src.txt --origin https://example.invalid/sla --media-type text/plain | jid)
id=$(printf 'vendor SLA is 99.9 percent\n' | $Z claim draft --tier projects --title SLA --basis evidence --evidence $e | jid); $Z claim approve $id >/dev/null; $Z reindex >/dev/null
ls -l $W/evidence/sources/$e/; cat $W/evidence/sources/$e/source.yaml
chmod u+w $W/evidence/sources/$e/raw; printf 'vendor SLA is 50%%\n' > $W/evidence/sources/$e/raw
echo "-- ask after raw edit"; $Z ask vendor SLA 2>&1 | grep -m1 '"status"\|evidence\|stale'
echo "-- reindex"; $Z reindex 2>&1 | grep -E '"rebuild_state"|"error"'
