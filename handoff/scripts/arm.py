# Plant each of the last N entries of a sabotage file by hand, run its witness (lib tests
# only), restore the file. Run from the repository root:
#   handoff/scripts/arm.py sabotage/entries/dns.txt 3
# RED = the witness failed (armed); SURVIVED = a hole; BROKEN = did not build or did not run.
import sys, subprocess, re, shutil
path, n = sys.argv[1], int(sys.argv[2])
S = __import__("os").path.dirname(__import__("os").path.abspath(__file__))
text = open(path).read()
entries = text.split("\n=== ")[-n:]
for e in entries:
    name = e.split("\n", 1)[0]
    f = re.search(r"^file: (.+)$", e, re.M).group(1)
    pkg, test = re.search(r"^witness: (\S+) (\S+)$", e, re.M).groups()
    old = e.split("--- old\n", 1)[1].split("--- new\n", 1)[0]
    new = e.split("--- new\n", 1)[1]
    new = new.rstrip("\n") + "\n" if new.strip() else new
    src = open(f).read(); assert src.count(old) == 1, (name, old)
    shutil.copy(f, f + ".arm-bak")
    open(f, "w").write(src.replace(old, new, 1))
    try:
        r = subprocess.run(f"{S}/memcap.sh 10 {S}/testenv.sh cargo test -q -p {pkg} --lib -- --exact {test}",
                           shell=True, capture_output=True, text=True, timeout=2400)
        out = r.stdout + r.stderr
        ran = "1 passed" in out or "1 failed" in out
        verdict = "RED" if "1 failed" in out else ("BROKEN" if not ran else "SURVIVED")
        print(f"{verdict:9} {name}", flush=True)
    finally:
        shutil.move(f + ".arm-bak", f)
