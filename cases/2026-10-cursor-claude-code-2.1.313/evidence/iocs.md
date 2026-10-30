# IOCs (réseau désarmé avec [.])

Source : SRC-001 et SRC-002 (OX Security). Ces IOCs ne sont pas tous vérifiés par nous ; seul le test négatif local est de première main (experiment-log.md).

## Paquet
| Élément | Valeur | Source |
|---|---|---|
| Extension | `anthropic.claude-code` **2.1.313** (Cursor Marketplace) | toutes |
| VSIX darwin-arm64 SHA-256 | `432ccdee3801f99e52b8fe31f69ea9870118e96ea7ef9ecabed1479621b5ab62` | OX |
| VSIX win32-x64 SHA-256 | `3de1722901165769893bef57c72594e9a54459faa23f3091b136b79966edd081` | OX |
| `extension.js` SHA-256 | `ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15` | OSM (plateforme non précisée) |
| Clé privée de tunnel intégrée SHA-256 | `7e0a52885fadee05544a9e99eb18c792bec05900a5e1a66d68f8383decb0e278` | OSM |

## Clés SSH
- Clé autorisée ajoutée : `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P svc-telemetry`
- Empreinte : `SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk`
- Empreinte de la clé de tunnel : `SHA256:KOAU57+ZG6u3MG4WwzPzPX2O5YEe9qdOC1Bl+6MVyDQ`

## Réseau
- `134[.]209[.]82[.]225` : SSH 22 (`tunnel@`), HTTP 8099 `POST /beacon` ; `127.0.0.1:8099/beacon` (leurre/loopback)
- `ifconfig[.]me`, `api[.]ipify[.]org` : services légitimes, non indicateurs seuls

## Fichiers / persistance
| OS | Artefact |
|---|---|
| macOS | `~/.ssh/authorized_keys`, `~/.config/.smt`, `~/.config/.smtk`, `$TMPDIR/.stk_<10 hex>`, `~/Library/LaunchAgents/com.apple.sysmond.plist` (label `com.apple.sysmond`) |
| Linux (SRC-001/004 seulement) | mêmes fichiers `~/.config`, crontab `@reboot` |
| Windows | `.ssh\authorized_keys`, `.config\smt.cmd`, `.config\smtk`, `%TEMP%\.stk_<10 hex>`, tâche `SysMon`, repli `Startup\sysmon.cmd` |

## Lignes de commande
`ssh -N -R '*:0:localhost:22'` · `autossh -M 0` · options `StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`, `ServerAliveInterval=30`, `ServerAliveCountMax=3`, `ExitOnForwardFailure=yes`, `IdentitiesOnly=yes` · `systemsetup -setremotelogin on` · `schtasks /create /tn SysMon` · `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`
