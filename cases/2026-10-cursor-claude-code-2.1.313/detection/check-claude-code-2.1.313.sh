#!/usr/bin/env bash
# Vérification en LECTURE SEULE des indicateurs de l'incident « Claude Code 2.1.313 »
# (Cursor Marketplace, 2026-10-29). Ne modifie rien, ne supprime rien.
# Usage : ./check-claude-code-2.1.313.sh [HOME_A_VERIFIER]
set -u
H="${1:-$HOME}"
KEY_COMMENT="svc-telemetry"
KEY_BLOB="AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P"
C2_IP="134.209.82.225"
hits=0
hit() { echo "[!] $*"; hits=$((hits+1)); }
ok()  { echo "[ok] $*"; }

# 1. Extensions installées (VS Code, Cursor, Windsurf, VSCodium)
for root in .vscode .cursor .windsurf .vscode-oss; do
  for d in "$H/$root/extensions"/anthropic.claude-code-*; do
    [ -e "$d" ] || continue
    case "$d" in
      *claude-code-2.1.313*) hit "version malveillante installée : $d" ;;
      *) ok "extension présente (autre version) : $(basename "$d")" ;;
    esac
    if grep -q -E "$C2_IP|$KEY_COMMENT|com\.apple\.sysmond" "$d/extension.js" 2>/dev/null; then
      hit "chaîne IOC trouvée dans $d/extension.js"
    fi
  done
done

# 2. Clé SSH autorisée
AK="$H/.ssh/authorized_keys"
if [ -f "$AK" ]; then
  if grep -q -E "$KEY_COMMENT|$KEY_BLOB" "$AK"; then hit "clé $KEY_COMMENT présente dans $AK"; else ok "authorized_keys sans la clé de l'incident"; fi
else ok "pas de authorized_keys"; fi

# 3. Fichiers de persistance
for f in "$H/.config/.smt" "$H/.config/.smtk" "$H/Library/LaunchAgents/com.apple.sysmond.plist"; do
  [ -e "$f" ] && hit "fichier de persistance : $f"
done
for f in "${TMPDIR:-/tmp}"/.stk_*; do [ -e "$f" ] && hit "clé de tunnel temporaire : $f"; done

# 4. Éléments système (seulement pour le profil réel)
if [ "$H" = "$HOME" ]; then
  crontab -l 2>/dev/null | grep -q -E "\.smt|@reboot.*\.config" && hit "entrée crontab suspecte"
  launchctl list 2>/dev/null | grep -q "com.apple.sysmond" && hit "LaunchAgent com.apple.sysmond chargé"
  ps -axo pid,command 2>/dev/null | grep -E "ssh -N|autossh" | grep -E "\-R '?\*:0:localhost:22" | grep -v grep \
    && hit "tunnel SSH inversé actif"
  (netstat -an 2>/dev/null || ss -tn 2>/dev/null) | grep -q "$C2_IP" && hit "connexion vers $C2_IP"
fi

echo "---"
[ "$hits" -eq 0 ] && echo "Aucun indicateur trouvé." || echo "$hits indicateur(s) : isoler la machine, conserver les preuves, ne rien supprimer avant collecte."
exit $([ "$hits" -eq 0 ] && echo 0 || echo 1)
