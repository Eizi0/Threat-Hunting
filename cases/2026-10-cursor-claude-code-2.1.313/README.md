# Extension Claude Code 2.1.313 piégée (Cursor Marketplace)

Le 29 octobre 2026, la marketplace de Cursor a servi pendant environ 11 heures une version modifiée de l'extension `anthropic.claude-code` : clé SSH de l'attaquant ajoutée, tentative de tunnel inversé, persistance qui survit à la désinstallation. Cursor parle d'au plus 5 000 utilisateurs exposés.

Article : https://www.jeovany.com/blog/claude-code-cursor-porte-derobee-ssh/

## Contenu

| Fichier | Rôle |
|---|---|
| [sources.md](sources.md) | Sources lues, fiabilité, sources non lues |
| [claims.md](claims.md) | 16 affirmations avec statut de preuve et divergences entre sources |
| [evidence/iocs.md](evidence/iocs.md) | Indicateurs de compromission (réseau désarmé) |
| [evidence/auditd-simulation-raw.log](evidence/auditd-simulation-raw.log) | Enregistrements `auditd` bruts de la simulation en VM |
| [experiment-log.md](experiment-log.md) | Expériences, résultats et limites |
| [detection/](detection/) | 3 règles Sigma et un script de vérification en lecture seule |

## Vérifier un poste

```bash
./detection/check-claude-code-2.1.313.sh            # profil de l'utilisateur courant
./detection/check-claude-code-2.1.313.sh /chemin    # un autre répertoire personnel
```

Le script ne modifie rien. Code de sortie 0 : aucun indicateur ; 1 : au moins un indicateur, isoler la machine et conserver les preuves avant tout nettoyage. Testé sur un poste macOS sain (0 indicateur) et sur un faux profil contenant des artefacts inertes (6 indicateurs). Non testé sur un vrai échantillon, ni sous Windows.

## Limites

- La simulation rejoue les comportements décrits en `bash` sur Debian, avec le `sshd` local comme faux serveur. Ni macOS ni Windows, pas de redémarrage pour le `@reboot`, pas de Wazuh.
- Les règles Sigma passent `sigma check` et `sigma convert` mais n'ont pas été exécutées dans un moteur de détection.
- Non lus : l'annonce de Cursor sur X, un éventuel communiqué d'Anthropic, The Hacker News (erreur 403).
