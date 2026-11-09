. "$(dirname "$0")/env.sh"
fresh view
id=$(printf 'acquisition target is Acme\n' | $Z claim draft --tier projects --title 'M&A' --basis owner | jid); $Z claim approve $id >/dev/null
$Z view > $S/view.out 2>&1 & pid=$!
for i in $(seq 50); do grep -q http $S/view.out && break; sleep 0.1; done
url=$(grep -o 'http://127.0.0.1:[0-9]*' $S/view.out | head -1)
# a DNS-rebound page sends its own hostname; the server does not care
curl -s -H 'Host: attacker.example' $url/api/claims | head -c 400; echo
kill $pid
