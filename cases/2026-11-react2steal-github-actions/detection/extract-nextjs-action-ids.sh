#!/usr/bin/env bash
# Génère un pipeline pySigma contenant les identifiants de Server Actions d'un build Next.js.
# Usage : ./extract-nextjs-action-ids.sh <dossier-de-l-application> > nextjs-action-ids.pipeline.yml
# À relancer à chaque déploiement : les identifiants changent à chaque build.
set -euo pipefail
M="${1:?chemin du dossier applicatif}/.next/server/server-reference-manifest.json"
[ -f "$M" ] || { echo "manifeste introuvable : $M (lancer après next build)" >&2; exit 1; }
node -e '
const m = require(process.argv[1]);
const ids = [...new Set([...Object.keys(m.node || {}), ...Object.keys(m.edge || {})])];
if (!ids.length) { console.error("aucune Server Action dans ce build"); }
console.log("name: nextjs-action-ids\npriority: 10\ntransformations:\n  - id: nextjs_action_ids\n    type: value_placeholders\n    include: [nextjs_action_ids]");
console.log("vars:\n  nextjs_action_ids:");
for (const id of ids.length ? ids : ["__aucune_action__"]) console.log("    - \"" + id + "\"");
' "$(cd "$(dirname "$M")" && pwd)/$(basename "$M")"
