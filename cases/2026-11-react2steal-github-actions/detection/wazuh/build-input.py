"""Construit les événements de test Wazuh à partir des preuves du labo. Chaque ligne : {"label", "attendu", "log_format", "event"}."""
import json, re, sys, collections
from pathlib import Path
ev = Path(sys.argv[1]); out = []
def web(f):
    for l in (ev / f).read_text().splitlines():
        if '{"time"' in l:
            j = json.loads(l[l.index('{"time"'):])
            # vérité terrain = origine de la requête (sonde du labo), pas la règle testée
            probe_post = j["method"] == "POST" and ("bissa_cve_boundary" in j["content_type"] or j["content_type"].endswith("boundary=b"))
            atk = bool(j["x_middleware_subrequest"]) or "/_next/image?url=http" in j["uri"] or "%68%74" in j["uri"] or probe_post
            out.append({"label": f"web {f}", "attendu": "attaque" if atk else "légitime", "log_format": "json", "event": json.dumps(j, ensure_ascii=False)})
for f in ["lab-run-1.log", "lab-baseline.log", "lab-run-exp3.log", "matrix/15.5.6.log", "variants/latest.log", "variants/15.5.6.log", "variants/16.1.7.log"]: web(f)
for f in ["matrix/15.5.29.log", "matrix/16.1.7.log", "variants/15.5.6.log", "variants/16.1.7.log", "matrix/15.5.6.log"]:
    for l in (ev / f).read_text().splitlines():
        if "next.log:" in l:
            msg = l.split("next.log:", 1)[1].strip()
            # lignes de continuation et erreurs génériques : pas des signaux visés par les règles
            att = "hors périmètre" if (msg.startswith("Read more") or "Connection closed" in msg) else "attaque"
            out.append({"label": f"app {f}", "attendu": att, "log_format": "syslog", "event": "nextjs: " + msg})
# auditd : fusion des enregistrements d'un même événement (comme log_format audit de l'agent)
groups = collections.OrderedDict()
for l in (ev / "host/audit-since-start.log").read_text(errors="replace").splitlines():
    m = re.search(r"msg=audit\(([\d.]+:\d+)\)", l)
    if m: groups.setdefault(m.group(1), []).append(l)
phases = [(float(t), n) for t, n in (x.split() for x in (ev / "host/phases.txt").read_text().splitlines())]
for k, recs in groups.items():
    if 'key="r2s_' not in recs[0] and "key=r2s_" not in recs[0]: continue
    ts = float(k.split(":")[0]); ph = [n for t, n in phases if ts >= t][-1]
    sens = any(s in " ".join(recs) for s in ("r2s_cloud_creds", "r2s_k8s_token"))
    out.append({"label": f"auditd {ph}", "attendu": "attaque" if (sens and ph == "SIMULATION") else "légitime", "log_format": "audit", "event": " ".join(recs)})
for l in (ev / "host/dnsmasq.log").read_text().splitlines():
    if "query[" in l:
        # le fichier dnsmasq n'a pas de nom d'hôte ; syslog l'ajouterait (format « date hôte programme[pid]: »)
        out.append({"label": "dns", "attendu": "attaque", "log_format": "syslog", "event": re.sub(r"^(\w{3} +\d+ [\d:]+) ", r"\1 lab-vm ", l)})
Path(sys.argv[2]).write_text("\n".join(json.dumps(o, ensure_ascii=False) for o in out) + "\n")
print(len(out), "événements", collections.Counter((o["label"].split()[0], o["attendu"]) for o in out))
