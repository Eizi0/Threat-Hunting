# Indicateurs (repris de SRC-001, non vérifiés sur les dépôts de la campagne)

## Côté serveur web victime
- En-tête `x-middleware-subrequest` (valeur efficace : nom du middleware répété cinq fois, séparé par `:`)
- `GET /_next/image?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/&w=64&q=75`, puis le même chemin suivi du nom du rôle
- `Next-Action: x`, éventuellement `x-action-id: x`, `Transfer-Encoding: chunked`, padding de 8 192 octets, octet nul avant `multipart/form-data`
- Boundary multipart `bissa_cve_boundary` (une variante la rend aléatoire)
- Sortant depuis le serveur web : appels aux API d'OpenAI, Anthropic, Gemini, DeepSeek, OpenRouter… avec l'agent utilisateur `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36`, `max_tokens: 20`, modèles `gpt-4o-mini`, `claude-3-5-haiku-latest`

## Côté GitHub
- Dépôts `ci-wk-<n>` ; workflow `.github/workflows/scan.yml` (`workflow_dispatch`, `contents: write`, `timeout-minutes: 350`)
- Fichiers `bin/prefilter_nextjs.py`, `bin/batch_output.py`, `bin/fast_recon.js`, `hosts_<date>_<heure>.txt`, dossier `vulnerables/`
- Auteur de commit `w <w@w>`, messages `chunk` et `results <epoch>`
- Compte `dascxzcw` (piste principale de SRC-001, désormais 404)
- wfx-loot : branche `wfx-docs`, fichier `docs/wfx-audit.md` (blob `ee6e5addfe591923fc385553cb66cf0d25634a6b`), PR « docs: dependency audit notes », commits « docs: add dependency audit notes », « ci: refresh build cache », « ci: restore »
- Non attribué : branches `ci-sync-<6 caractères>`, commit « ci: sync config », workflow `sync-check` qui encode `${{ toJSON(secrets) }}` en base32
