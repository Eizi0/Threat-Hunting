# Journal d'expériences

## EXP-001 — Script de vérification, test négatif et positif (2026-10-30)
- `detection/check-claude-code-2.1.313.sh`, lecture seule.
- **Poste réel macOS, sain** : extensions `anthropic.claude-code` installées via VS Code, aucune en 2.1.313 ; aucune chaîne IOC dans leur `extension.js` ; aucun fichier de persistance, aucun LaunchAgent, aucune crontab, aucun processus `ssh -N`, aucune connexion vers l'IP. Résultat : 0 indicateur, code de sortie 0.
- **Faux profil** (`mktemp`, fichiers inertes) avec une extension 2.1.313 factice, la clé `svc-telemetry`, `.smt`, `.smtk` et `com.apple.sysmond.plist` : 6 indicateurs, code de sortie 1.
- **Limites** : le test positif utilise des fichiers factices, il valide la logique du script et non la fidélité à un vrai échantillon. Les contrôles crontab, launchctl, processus et connexions ne tournent que sur le profil réel. `systemsetup -getremotelogin` demande l'administrateur et n'a pas été lu.

## EXP-002 — Règles Sigma (2026-10-30)
- Trois règles dans `detection/`. `sigma check` : 0 erreur. `sigma convert -t splunk` : OK.
- La règle sur le tunnel a été confrontée à la ligne de commande réelle capturée en EXP-003 (décodée depuis `PROCTITLE`) : elle correspond. Aucune règle n'a été exécutée dans un moteur de détection.

## EXP-003 — Simulation des comportements en VM (2026-10-30)
- **Environnement** : VM Debian 12 de laboratoire, `auditd` et `autossh` installés pour l'occasion. Deux comptes jetables : `labvictim` (la « victime ») et `labrelay` (un relais qui n'accepte que la clé de tunnel). **Aucun échantillon réel, aucune connexion externe** : le « serveur de l'attaquant » est le `sshd` local de la VM, joint par `127.0.0.1`. Les clés sont générées pour le labo (le commentaire `svc-telemetry` est reproduit, la vraie clé de l'attaquant n'est pas utilisée).
- **Règles auditd** : `-w authorized_keys -p wa`, `-w ~/.config -p wa`, `-w /var/spool/cron/crontabs -p wa`, `execve` de `/usr/bin/ssh` et `/usr/bin/autossh`.
- **Simulation (en bash, pas en Node)** : ajout de la clé, création de `.config/.smt` et `.smtk` (inertes), clé de tunnel copiée dans `/tmp/.stk_<10 hex>`, crontab `@reboot`, puis `ssh -N -R '*:0:localhost:22' ... labrelay@127.0.0.1` avec les options publiées par OX.
- **Résultats** (preuve : `evidence/auditd-simulation-raw.log`) :
  - L'ouverture de `authorized_keys` (clé `lab_authkeys`), la création de `.smt` et `.smtk` (`lab_config`), l'écriture de la crontab (`crontabs/labvictim`, `lab_cron`) et l'`execve` de `ssh` avec la ligne de commande complète (`lab_ssh`) sont tous enregistrés.
  - Le tunnel s'établit : « Allocated port 39199 for remote forward to localhost:22 ». Le port est alloué par le serveur. Il écoute en loopback car le `sshd` du relais a `GatewayPorts` par défaut ; sur le vrai serveur, c'est le réglage de l'attaquant.
  - Le journal `sshd` du relais montre `Accepted publickey for labrelay from 127.0.0.1`.
  - La ligne de commande est stockée en **hexadécimal** dans `PROCTITLE`, avec des octets nuls entre les arguments : il faut la décoder avant de lui appliquer une règle.
- **Constat qui a changé une règle** : l'ajout de la clé par redirection shell ne produit **aucune ligne de commande** contenant `svc-telemetry`, seulement un `openat` sur le chemin. La première règle (commande contenant `authorized_keys` et `svc-telemetry`) ne se serait jamais déclenchée ; elle a été remplacée par `authorized_keys_modified_auditd.yml`, fondée sur l'écriture du fichier.
- **Non expliqué** : `ausearch -k <clé>` (avec et sans `-i`) a répondu « no matches » alors que `audit.log` contient les événements avec la clé. Les preuves ont été extraites par `grep` sur le log brut.
- **Limites** : bash et non le `fs` de Node comme le vrai chargeur ; ni macOS (LaunchAgent) ni Windows ; le `@reboot` a été écrit et relu, pas exercé par un redémarrage ; Wazuh non installé, aucune règle Wazuh testée.
- **Nettoyage** : tunnel arrêté, `/tmp/.stk_*` supprimé.
- **Anonymisation du log** : la session d'administration de la VM et le nom d'hôte ont été retirés ou remplacés avant publication ; les enregistrements de la simulation sont inchangés.
