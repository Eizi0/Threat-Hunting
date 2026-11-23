"""Regroupe les enregistrements auditd par événement (horodatage:numéro), les rattache à la phase de l'expérience
et écrit un JSON par ligne. Usage : python -I analyze-audit.py <dossier r2s-evidence>"""
import json, re, sys, collections
from pathlib import Path
d = Path(sys.argv[1])
phases = [(float(t), n) for t, n in (l.split() for l in (d / "phases.txt").read_text().splitlines())]
def phase(ts):
    cur = "AVANT"
    for t, n in phases:
        if ts >= t: cur = n
    return cur
ev = collections.OrderedDict()
for line in (d / "audit-since-start.log").read_text(errors="replace").splitlines():
    m = re.search(r"msg=audit\((\d+\.\d+):(\d+)\)", line)
    if not m: continue
    e = ev.setdefault(m.group(2), {"ts": float(m.group(1)), "types": [], "names": []})
    typ = re.match(r"type=(\S+)", line).group(1); e["types"].append(typ)
    kv = dict(re.findall(r'(\w+)=("[^"]*"|\S+)', line))
    if typ == "SYSCALL":
        for k in ("syscall", "success", "exe", "comm", "pid", "ppid", "uid", "key"): e[k] = kv.get(k, "").strip('"')
    elif typ == "PATH" and kv.get("name"):
        n = kv["name"]; e["names"].append(n.strip('"') if n.startswith('"') else bytes.fromhex(n).decode(errors="replace") if re.fullmatch(r"[0-9A-F]+", n) else n)
    elif typ == "SOCKADDR":
        s = kv.get("saddr", "")
        if s.startswith("0200") and len(s) >= 16:  # AF_INET
            e["dest"] = f"{'.'.join(str(int(s[i:i+2],16)) for i in (8,10,12,14))}:{int(s[4:8],16)}"
out = d / "audit-events.jsonl"
with out.open("w") as f:
    for sid, e in ev.items():
        if not e.get("key", "").startswith('r2s_') and not e.get("key", "").startswith('"r2s_'): continue
        r = {"serial": sid, "phase": phase(e["ts"]), "key": e["key"].strip('"'), "syscall": e.get("syscall"), "success": e.get("success"),
             "exe": e.get("exe"), "comm": e.get("comm"), "pid": e.get("pid"), "ppid": e.get("ppid"), "uid": e.get("uid"),
             "name": " | ".join(n for n in e["names"] if n not in ("(null)",)), "dest": e.get("dest", "")}
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
rows = [json.loads(l) for l in out.read_text().splitlines()]
summ = collections.Counter((r["phase"], r["key"], r["exe"]) for r in rows)
for (p, k, x), c in sorted(summ.items()): print(f"{p:11} {k:16} {x:30} {c}")
print("\nlectures de fichiers sensibles :")
for r in rows:
    if r["key"] in ("r2s_cloud_creds", "r2s_k8s_token", "r2s_dotenv"): print(f"  {r['phase']:11} {r['key']:16} {r['exe']} {r['syscall']} ok={r['success']} {r['name']}")
print("\nconnexions sortantes (hors boucle vers le serveur lui-même) :")
for r in rows:
    if r["key"] == "r2s_connect" and r["dest"] and not r["dest"].endswith(":3000"): print(f"  {r['phase']:11} {r['exe']} -> {r['dest']}")
print("\nprocessus lancés par labweb :")
for r in rows:
    if r["key"] == "r2s_exec": print(f"  {r['phase']:11} {r['exe']} (ppid {r['ppid']})")
