#!/bin/bash
# Trafic légitime : base de faux positifs
nginx; npx next start -H 127.0.0.1 -p 3000 >/tmp/next.log 2>&1 &
for i in $(seq 30); do curl -s -o /dev/null 127.0.0.1:3000 && break; sleep 1; done
B=http://127.0.0.1:8080
curl -s -o /dev/null $B/; curl -s -o /dev/null $B/login; curl -s -o /dev/null -b session=1 $B/admin
curl -s -o /dev/null -w "image locale %{http_code}\n" "$B/_next/image?url=%2Flogo.png&w=64&q=75"
html=$(curl -s $B/form)
# Le formulaire progressif contient l'ID d'action dans un champ caché $ACTION_ID_<id>
AID=$(echo "$html" | grep -o '\$ACTION_ID_[0-9a-f]*' | head -1 | sed 's/\$ACTION_ID_//')
echo "ID d'action réel : $AID (longueur ${#AID})"
# Appel tel qu'émis par le client React (fetch avec en-tête Next-Action)
curl -s -o /dev/null -w "server action légitime %{http_code}\n" -X POST -H "Next-Action: $AID" -H 'Content-Type: text/plain;charset=UTF-8' -H 'Accept: text/x-component' --data '[{"name":"x"}]' $B/form
# Soumission sans JS (formulaire HTML pur, sans en-tête Next-Action)
curl -s -o /dev/null -w "soumission HTML pure %{http_code}\n" -X POST -F "\$ACTION_ID_$AID=" -F name=x $B/form
sleep 1; cat /var/log/nginx/detect.json; grep save /tmp/next.log
