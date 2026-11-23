"""Exécute les requêtes SQL de sigma convert -t sqlite sur les preuves hôte (événements auditd fusionnés par
lab-host/analyze-audit.py + journal dnsmasq). Usage : python -I run-rules-on-host-logs.py <evidence/host> < requetes.sql"""
import json, re, sqlite3, sys
from pathlib import Path
d = Path(sys.argv[1]); db = sqlite3.connect(":memory:")
db.create_function("REGEXP", 2, lambda p, v: v is not None and re.search(p, v) is not None)
cols = ["src","phase","key","syscall","success","exe","comm","pid","ppid","uid","name","dest","query","serial"]
db.execute(f"CREATE TABLE logs ({','.join(cols)})")
for l in (d / "audit-events.jsonl").read_text().splitlines():
    r = json.loads(l); r["src"] = "auditd"
    db.execute(f"INSERT INTO logs ({','.join(r)}) VALUES ({','.join('?'*len(r))})", list(r.values()))
for l in (d / "dnsmasq.log").read_text().splitlines():
    m = re.search(r"query\[(\w+)\] (\S+) from", l)
    if m: db.execute("INSERT INTO logs (src, query, syscall) VALUES ('dns', ?, ?)", (m.group(2), m.group(1)))
print(db.execute("SELECT count(*) FROM logs").fetchone()[0], "événements (auditd r2s_* + requêtes DNS)\n")
for q in [q.strip() for q in sys.stdin.read().split("\n\n") if q.strip().startswith("SELECT")]:
    rows = [dict(zip(cols, r)) for r in db.execute(q).fetchall()]
    print(f"-- {q[:100]}...\n   {len(rows)} correspondance(s)")
    for r in rows: print("   ", r["src"], r["phase"] or "", r["exe"] or "", r["name"] or "", r["query"] or "", r["syscall"] or "")
    print()
