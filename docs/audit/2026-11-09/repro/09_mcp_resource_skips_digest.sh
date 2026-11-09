. "$(dirname "$0")/env.sh"
fresh mcpdigest
id=$(printf 'the deploy window is tuesday\n' | $Z claim draft --tier projects --title 'Deploy window' --basis owner | jid); $Z claim approve $id >/dev/null; $Z reindex >/dev/null
sed -i 's/tuesday/friday (tampered)/' $W/wiki/projects/$id.md
{ echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}'
  echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  echo "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/read\",\"params\":{\"uri\":\"zbrain://workspace/ws/claim/$id\"}}"
} | timeout 5 $Z mcp serve 2>/dev/null | tail -1 | python3 -c 'import json,sys; c=json.loads(json.loads(sys.stdin.read())["result"]["contents"][0]["text"]); print({k:v for k,v in c.items() if k in ("Status","Body")})'
