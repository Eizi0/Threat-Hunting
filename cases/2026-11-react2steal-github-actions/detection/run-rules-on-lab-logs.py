"""Exécute les requêtes SQL générées par sigma convert -t sqlite sur les journaux capturés en labo.
Usage : python run-rules-on-lab-logs.py <dossier evidence> [fichiers relatifs...] < requetes.sql"""
import json, re, sqlite3, sys
from pathlib import Path
ev = Path(sys.argv[1])
db = sqlite3.connect(":memory:")
db.create_function("REGEXP", 2, lambda p, v: v is not None and re.search(p, v) is not None)
cols = ["src","time","method","uri","status","ua","content_type","next_action","x_action_id",
        "x_middleware_subrequest","transfer_encoding","message"]
db.execute(f"CREATE TABLE logs ({','.join(cols)})")
files = sys.argv[2:] or ["lab-run-1.log", "lab-baseline.log", "lab-run-exp3.log"]
for f in files:
    for line in (ev / f).read_text().splitlines():
        if '{"time"' in line:
            r = json.loads(line[line.index('{"time"'):]); r["src"] = f
            db.execute(f"INSERT INTO logs ({','.join(r)}) VALUES ({','.join('?'*len(r))})", list(r.values()))
        elif "next.log:" in line or "valid image" in line:
            db.execute("INSERT INTO logs (src, message) VALUES (?,?)", (f + " [next.js]", line.strip()))
total = db.execute("SELECT count(*) FROM logs").fetchone()[0]
print(f"{total} événements chargés\n")
for q in [q.strip() for q in sys.stdin.read().split("\n\n") if q.strip().startswith("SELECT")]:
    rows = db.execute(q).fetchall()
    print(f"-- {q[:110]}...\n   {len(rows)} correspondance(s)")
    for r in rows:
        d = dict(zip(cols, r))
        print("   ", d["src"], d["method"] or "", d["uri"] or "", d["status"] or "", d["message"] or "", "|", d["x_middleware_subrequest"] or d["next_action"] or "")
    print()
