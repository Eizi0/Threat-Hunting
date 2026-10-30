# Registre des affirmations

Dernière mise à jour : 2026-10-30. Statut de preuve : **A** incident rapporté · **B** analyse statique tierce · **C** vérifié par nous · **D** déduit.

| # | Affirmation | Sources | Statut | Formulation autorisée |
|---|---|---|---|---|
| C1 | Une version 2.1.313 modifiée de `anthropic.claude-code` a été servie sur la **Cursor Marketplace** le 29/10/2026 | SRC-001, 002, 003, 004 (toutes reprennent Cursor) | Confirmé par l'éditeur de la marketplace | « Cursor indique… » |
| C2 | Fenêtre ≈ 02h27 → 13h35 PT (≈ 11 h), au plus 5 000 utilisateurs | SRC-002, 003, 004 | Chiffre de Cursor, plafond non mesuré | « au plus 5 000 selon Cursor » ; ne pas parler de victimes |
| C3 | Anthropic n'a pas développé cette version | Cursor via SRC-003/004 | Déclaration de Cursor ; pas de texte Anthropic lu | Attribuer à Cursor |
| C4 | Seule la marketplace Cursor a distribué le paquet ; npm, VS Code Marketplace, Open VSX non touchés | SRC-001, 003 (mise à jour) | **Divergent au départ** : Phorion voyait Open VSX (SRC-004), contesté par Manifold Security ; rectifié par Cursor | Raconter la rectification |
| C5 | Un IIFE de 66 lignes est inséré avant le bundle légitime, exécuté au chargement, sans interaction avec Claude | SRC-001, 003, 004 | B | OK |
| C6 | Le loader ajoute la clé `svc-telemetry` (ed25519), ouvre `ssh -N -R '*:0:localhost:22'` vers `tunnel@134.209.82.225`, envoie un beacon à `:8099/beacon` | SRC-001, 002 | B, deux analyses concordantes | OK |
| C7 | Persistance macOS (LaunchAgent `com.apple.sysmond`) et Windows (tâche `SysMon`) | SRC-001, 002 | B | OK |
| C8 | Persistance **Linux** (cron `@reboot`) | SRC-001, SRC-004 (Help Net Security) ; **absente d'OX (SRC-002)** qui n'analyse que darwin-arm64 et win32-x64 | **À nuancer** : décrite par deux sources, non confirmée sur un paquet Linux | « décrite par… mais OX ne l'a pas observée » |
| C9 | L'activation de SSH échoue presque toujours sans droits admin | SRC-002 ; Cursor (SRC-004) | B | OK |
| C10 | « Ça limite l'impact » (Cursor) vs « un bug de vérification ne protège pas si Remote Login est déjà actif » (Phorion) | SRC-004 | **Divergent** | Présenter les deux ; notre lecture : la clé et le tunnel restent exploitables si sshd est déjà joignable |
| C11 | Désinstaller l'extension ne supprime pas la porte dérobée | SRC-001, 003, 004 | B (scripts autonomes déposés) | OK, solide |
| C12 | Aucun second étage téléchargé | SRC-001 seul | B, source unique | « selon OpenSourceMalware » |
| C13 | Le serveur attaquant a été mis hors ligne avec l'hébergeur | SRC-003, 004 (Cursor) | A | Cela réduit la valeur du beacon mais pas celle des clés déjà posées |
| C14 | Mode d'accès de l'attaquant à la publication (compte éditeur, token) | **Aucune source** | Inconnu | Dire « non établi » |
| C15 | Le script de vérification détecte les artefacts décrits (faux profil) et ne signale rien sur un poste réel sain | SRC-007 | **C** | Voir experiment-log (EXP-001) |
| C16 | Le hash `extension.js` de SRC-001 (`ecb58cb2…`) correspond au paquet darwin-arm64 / win32-x64 d'OX | — | **Non vérifié** : OX ne publie pas le hash d'extension.js, SRC-001 non plus ne dit pas quelle plateforme | Ne pas affirmer le lien |

Écart noté : SRC-001 attribue la date de publication au 29/10 mais l'article est daté du 30/10 09:42 UTC, ce qui est cohérent (publication de l'analyse le lendemain).
