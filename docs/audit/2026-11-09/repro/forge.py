# usage: forge.py <wiki_dir> <tier> <id> <title> <body> [extra zbrain yaml lines]
import sys,hashlib,os
wiki,tier,cid,title,body=sys.argv[1:6]; extra=sys.argv[6] if len(sys.argv)>6 else ""
ts="2026-01-01T00:00:00Z"
def doc(ver):
    return ("---\ntype: zbrain.claim\ntitle: "+title+"\ngenerated:\n    at: \""+ts+"\"\n    by: owner\n"+ver+
      "status: approved\nzbrain:\n    profile: zbrain.trusted-memory/v1\n    id: "+cid+"\n    tier: "+tier+"\n    basis: owner\n"+extra+
      "    transitions:\n        - kind: approve\n          at: \""+ts+"\"\n          by: owner\n---\n"+body+"\n")
d="sha256:"+hashlib.sha256(doc("").encode()).hexdigest()
open(os.path.join(wiki,tier,cid+".md"),"w").write(doc("verified:\n    at: \""+ts+"\"\n    by: owner\n    digest: "+d+"\n"))
