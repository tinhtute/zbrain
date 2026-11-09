. "$(dirname "$0")/env.sh"
fresh viewdigest
id=$(printf 'the deploy window is tuesday\n' | $Z claim draft --tier projects --title 'Deploy window' --basis owner | jid); $Z claim approve $id >/dev/null; $Z reindex >/dev/null
sed -i 's/tuesday/friday (tampered)/' $W/wiki/projects/$id.md        # no digest recompute
$Z reindex 2>&1 | grep -E '"rebuild_state"|"error"'
$Z ask deploy 2>&1 | head -1
$Z view > $S/view2.out 2>&1 & pid=$!
for i in $(seq 50); do grep -q http $S/view2.out && break; sleep 0.1; done
url=$(grep -o 'http://127.0.0.1:[0-9]*' $S/view2.out | head -1)
curl -s $url/api/claims | python3 -c 'import json,sys; [print(c["Status"], "|", c["Body"].strip()) for c in json.load(sys.stdin)]'
kill $pid
