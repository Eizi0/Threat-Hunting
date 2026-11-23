"""Envoie les événements étiquetés au socket wazuh-logtest (une session par fichier) et résume les règles déclenchées.
À lancer DANS le conteneur wazuh-manager : python3 run-logtest.py input.jsonl"""
import json, socket, struct, sys, collections
SOCK = "/var/ossec/queue/sockets/logtest"
def call(payload):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(SOCK)
    b = json.dumps(payload).encode(); s.sendall(struct.pack("<I", len(b)) + b)
    n = struct.unpack("<I", s.recv(4))[0]; data = b""
    while len(data) < n: data += s.recv(n - len(data))
    s.close(); return json.loads(data)
token = None; res = collections.Counter(); fires = collections.Counter(); details = []
for line in open(sys.argv[1]):
    e = json.loads(line)
    p = {"event": e["event"], "log_format": e["log_format"], "location": "r2s-lab"}
    if token: p["token"] = token
    r = call({"version": 1, "origin": {"name": "r2s", "module": "lab"}, "command": "log_processing", "parameters": p})
    if r.get("error"): print("ERREUR", r.get("message"), e["label"]); continue
    token = r["data"].get("token", token)
    rule = r["data"]["output"].get("rule", {}); rid = rule.get("id", ""); 
    ours = rid.startswith("1007") and rid != "100700"  # 100700 : règle de niveau 0 qui reconnaît seulement le format
    fires[(rid, rule.get("description", "")[:70])] += 1
    if e["attendu"] == "hors périmètre": res[(e["label"].split()[0], "hors périmètre")] += 1; continue
    verdict = {("attaque", True): "VP", ("attaque", False): "FN", ("légitime", True): "FP", ("légitime", False): "VN"}[(e["attendu"], ours)]
    res[(e["label"].split()[0], verdict)] += 1
    if verdict in ("FN", "FP"): details.append(f"{verdict} {e['label']} -> règle {rid or '-'} | {e['event'][:120]}")
print("Règles déclenchées :"); [print(f"  {c:3} {k[0]:>6} {k[1]}") for k, c in sorted(fires.items())]
print("Bilan :", dict(sorted(res.items())))
print("Faux négatifs / faux positifs :"); [print("  " + d) for d in details]
