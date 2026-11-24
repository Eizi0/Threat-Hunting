#!/bin/bash
# Expérience hôte React2STEAL sur la VM de labo (Debian 12, auditd). À lancer avec sudo.
set -u
E=/tmp/r2s-evidence; rm -rf $E; mkdir -p $E
mark(){ echo "$(date +%s.%N) $1" | tee -a $E/phases.txt; }
# 1. Trou noir DNS (dnsmasq dédié, résolveur système pointé dessus le temps de l'expérience)
systemctl stop dnsmasq 2>/dev/null; systemctl disable dnsmasq 2>/dev/null
UP=$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf); [ "$UP" = 127.0.0.1 ] && UP=${UPSTREAM_DNS:-1.1.1.1}  # résolveur amont si le système pointe déjà sur la boucle locale (pas Quad9 : service arrêté en France en novembre 2026)
sed "s/UPSTREAM_DNS/$UP/" /tmp/dnsmasq-r2s.conf > /etc/dnsmasq-r2s.conf; : > /var/log/dnsmasq-r2s.log
pkill -x dnsmasq; dnsmasq -C /etc/dnsmasq-r2s.conf
cp -n /etc/resolv.conf /etc/resolv.conf.r2s-backup; echo "nameserver 127.0.0.1" > /etc/resolv.conf
# 2. Règles auditd
# auditctl -R échoue en silence sur ce fichier (commentaires accentués) : chargement ligne par ligne
grep -v "^#" /tmp/audit.rules | grep . | while read -r l; do auditctl $l; done; auditctl -l | grep r2s_ > $E/audit-rules-loaded.txt
# 3. Démarrage de l'application (lecture légitime de .env attendue ici)
# le serveur se renomme next-server une fois lancé
pkill -u labweb -f "next-server|next start"; sleep 1
mark START
cd /srv/r2s-app && sudo -u labweb HOME=/home/labweb nohup npx next start -H 127.0.0.1 -p 3000 > $E/next.log 2>&1 &
for i in $(seq 60); do curl -s -o /dev/null 127.0.0.1:3000 && break; sleep 1; done; sleep 2
# 4. Trafic légitime
mark BASELINE
B=http://127.0.0.1:3000
for p in / /login /form; do curl -s -o /dev/null $B$p; done; curl -s -o /dev/null -b session=1 $B/admin
# (pas de requête /_next/image ici : sharp, natif, plante en « Bus error » sur le processeur virtuel QEMU sans AVX de la VM)
AID=$(curl -s $B/form | grep -o '\$ACTION_ID_[0-9a-f]*' | head -1 | sed 's/\$ACTION_ID_//'); curl -s -o /dev/null -X POST -F "\$ACTION_ID_$AID=" -F name=x $B/form
sleep 3
# 5. Simulation du comportement de fast_recon.js dans le processus Next.js
mark SIMULATION
curl -s $B/api/lab-sim > $E/lab-sim-response.json; sleep 3
mark END
# 6. Collecte
T0=$(awk '/START/{print int($1)}' $E/phases.txt)
awk -v t=$T0 -F'[(:]' '/msg=audit\(/{ split($0,a,"msg=audit\\("); split(a[2],b,":"); if (b[1]+0 >= t) print }' /var/log/audit/audit.log > $E/audit-since-start.log
grep -c . $E/audit-since-start.log
cp /var/log/dnsmasq-r2s.log $E/dnsmasq.log
# 7. Remise en état
pkill -u labweb -f "next-server|next start"; pkill -x dnsmasq
cp /etc/resolv.conf.r2s-backup /etc/resolv.conf
grep -v "^#" /tmp/audit.rules | grep . | sed -e 's/^-w /-W /' -e 's/^-a always,exit/-d always,exit/' | while read -r l; do auditctl $l; done
auditctl -l | grep -c r2s_ ; chmod -R a+r $E
