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
- **Constat qui a changé une règle** : lorsque l'ajout de la clé est fait par une redirection à l'intérieur d'un script lancé par fichier, le `PROCTITLE` est « bash » seul : aucune ligne de commande ne contient `svc-telemetry`, seulement un `openat` sur le chemin. La première règle (commande contenant `authorized_keys` et `svc-telemetry`) ne se serait donc pas déclenchée. **Nuance ajoutée en EXP-004** : avec `bash -c 'echo ... >> authorized_keys'`, la ligne de commande contient bien le nom de la clé. Selon la façon dont l'écriture est lancée, la ligne de commande est présente ou absente ; le vrai chargeur écrit depuis Node (hypothèse non vérifiée), donc on ne peut pas s'y fier. Règle remplacée par `authorized_keys_modified_auditd.yml`, fondée sur le fichier.
- **Non expliqué** : `ausearch -k <clé>` (avec et sans `-i`) a répondu « no matches » alors que `audit.log` contient les événements avec la clé. Les preuves ont été extraites par `grep` sur le log brut.
- **Limites** : bash et non le `fs` de Node comme le vrai chargeur ; ni macOS (LaunchAgent) ni Windows ; le `@reboot` a été écrit et relu, pas exercé par un redémarrage ; Wazuh non installé, aucune règle Wazuh testée.
- **Nettoyage** : tunnel arrêté, `/tmp/.stk_*` supprimé.
- **Anonymisation du log** : la session d'administration de la VM et le nom d'hôte ont été retirés ou remplacés avant publication ; les enregistrements de la simulation sont inchangés.

## EXP-004 — Trois écritures dans authorized_keys vues par auditd (2026-10-30)
- **But** : répondre à la remarque qu'un enregistrement `PATH` ne prouve pas qu'une écriture a réussi, et montrer un faux positif réel.
- **Environnement** : même VM et même règle `-w .../authorized_keys -p wa` qu'en EXP-003. Preuve : `evidence/auditd-authorized-keys-events.log`.
- **Événement 488 — écriture réussie, `bash -c 'echo "... svc-telemetry" >> ~/.ssh/authorized_keys'`** : `SYSCALL openat success=yes exit=3 a2=441` (`O_WRONLY|O_CREAT|O_APPEND`), `exe=/usr/bin/bash`, `uid=1001`, `auid=1000` ; `PATH name=.../authorized_keys nametype=NORMAL` ; `PROCTITLE` contient le nom de la clé.
- **Événement 501 — ajout légitime d'un administrateur, `sudo tee -a`** : même `PATH`, `success=yes`, mais `exe=/usr/bin/tee`, `uid=0`, `auid=1000`. C'est le faux positif réel : le `PATH` est identique, seul le `SYSCALL` (exécutable, uid) le distingue.
- **Événement 564 — tentative refusée** : fichier rendu immuable (`chattr +i`), puis `bash -c 'echo y >> ...'` : `SYSCALL openat success=no exit=-1`, mais un enregistrement `PATH` identique existe. **Un `PATH` seul n'est donc pas la preuve d'une écriture.** Le fichier a été remis en état (`chattr -i`, vérifié).
- **Non observé** : une tentative bloquée en amont (répertoire personnel inaccessible à un autre compte) n'a produit aucun événement, le refus ayant lieu avant l'atteinte du fichier surveillé.
- **Limites** : trois cas sur une VM, avec bash et `tee`. Le vrai chargeur écrit probablement avec Node, non reproduit. La corrélation par numéro de série entre `PATH` et `SYSCALL` n'a pas été implémentée dans un moteur : elle est décrite, pas exécutée.
