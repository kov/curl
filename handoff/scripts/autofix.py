# Apply rustc's machine-applicable suggestions for errors, once per span, across the given cargo build.
import json,subprocess,sys,collections
out=subprocess.run(sys.argv[1:],capture_output=True,text=True).stdout
edits=collections.defaultdict(list)
for line in out.splitlines():
    try: m=json.loads(line)
    except: continue
    if m.get("reason")!="compiler-message": continue
    msg=m["message"]
    for ch in msg.get("children",[]):
        for sp in ch.get("spans",[]):
            if sp.get("suggestion_applicability")=="MachineApplicable" and sp.get("suggested_replacement") is not None:
                edits[sp["file_name"]].append((sp["byte_start"],sp["byte_end"],sp["suggested_replacement"]))
n=0
for f,es in edits.items():
    b=open(f,'rb').read()
    for s,e,r in sorted(set(es),reverse=True):
        b=b[:s]+r.encode()+b[e:]; n+=1
    open(f,'wb').write(b)
print("applied",n)
