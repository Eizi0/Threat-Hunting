# Sources

Dernière mise à jour : 2026-10-30. Toutes lues le 2026-10-30 (WebFetch, résumé par modèle : les citations littérales sont à reverifier à la relecture finale).

| ID | Source | Auteur / date | Nature | Fiabilité |
|---|---|---|---|---|
| SRC-001 | OpenSourceMalware, « Trojanized Claude Code Extension Plants Persistent SSH Backdoor » — https://opensourcemalware.com/blog/trojanized-claude-code-extension-plants-persistent-ssh-backdoor | 2026-10-30 09:42 UTC | Analyse de l'extension.js (provenance du répertoire analysé « not established »), mise à jour Cursor en tête | Technique, détaillée ; échantillon d'origine non établie |
| SRC-002 | OX Security, « Compromised Claude Code Extension (2.1.313) in Cursor Marketplace… » — https://www.ox.security/blog/malicious-claude-code-extension-cursor-ssh-backdoor/ | Nir Zadok, 2026-10-30 | Analyse des VSIX darwin-arm64 et win32-x64, IOCs complets | Technique, source des hashes VSIX |
| SRC-003 | BleepingComputer — https://www.bleepingcomputer.com/news/security/malicious-claude-code-extension-on-cursor-planted-ssh-backdoors/ | Bill Toulas, 2026-10-30 10:36 | Reprise de l'annonce Cursor, fenêtre, 5 000 utilisateurs, correction Open VSX | Média, relaie Cursor |
| SRC-004 | Help Net Security — https://www.helpnetsecurity.com/2026/10/30/claude-code-extension-ssh-backdoor/ | 2026-10-30 | Reprise, cite Phorion et Manifold Security (Ax Sharma), divergence Open VSX et portée macOS, cron Linux | Média, contient les divergences |
| SRC-005 | The Hacker News — https://thehackernews.com/2026/10/official-claude-code-vs-code-extension.html | 2026-10 | **403 sur WebFetch** : non lue | — |
| SRC-006 | Annonce Cursor sur X — https://x.com/cursor_ai/status/2116074289053175808 | 2026-10-29/30 | Source primaire de l'éditeur de la marketplace, **non lue** (X inaccessible) ; citée par SRC-001 | Primaire, à lire à la main |
| SRC-007 | Tests de cette investigation | 2026-10-30 | Vérification d'un poste réel, script de vérification, simulation en VM | Preuve propre, voir experiment-log.md |

**Correction 2026-10-30** : une première version de ce tableau avait inversé The Hacker News (403, non lue) et Help Net Security (lue) ; les divergences et le cron Linux viennent de Help Net Security.

Non lus / non trouvés : l'avis officiel d'Anthropic (le texte cité « not developed by Anthropic » vient de Cursor, relayé par les médias), les scripts de nettoyage publiés par Cursor (cités par SRC-004, non récupérés).
