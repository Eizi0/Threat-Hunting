#!/usr/bin/env bash
# Génère un pipeline pySigma contenant les identifiants de Server Actions d'un ou plusieurs builds Next.js.
# Usage : ./extract-nextjs-action-ids.sh <dossier-app> [<dossier-app-2> ...] > nextjs-action-ids.pipeline.yml
# Plusieurs dossiers : union des identifiants (déploiement progressif, plusieurs instances ou versions en service).
# À relancer à chaque déploiement, et à garder étendu à l'ancien build tant que des clients peuvent l'utiliser.
set -euo pipefail
[ $# -ge 1 ] || { echo "usage : $0 <dossier-app> [...]" >&2; exit 2; }
files=()
for d in "$@"; do
  M="$d/.next/server/server-reference-manifest.json"
  [ -f "$M" ] || { echo "manifeste introuvable : $M (lancer après next build)" >&2; exit 1; }
  files+=("$(cd "$(dirname "$M")" && pwd)/$(basename "$M")")
done
node -e '
const ids = new Map();
for (const f of process.argv.slice(1)) {
  const m = require(f); const bid = require("fs").readFileSync(require("path").join(f, "../../BUILD_ID"), "utf8").trim();
  for (const id of [...Object.keys(m.node || {}), ...Object.keys(m.edge || {})]) ids.set(id, (ids.get(id) || []).concat(bid));
}
console.log("name: nextjs-action-ids\npriority: 10\ntransformations:\n  - id: nextjs_action_ids\n    type: value_placeholders\n    include: [nextjs_action_ids]");
console.log("vars:\n  nextjs_action_ids:");
if (!ids.size) { console.error("aucune Server Action dans ces builds"); console.log("    - \"__aucune_action__\""); }
for (const [id, b] of ids) console.log("    - \"" + id + "\"  # build " + b.join(", "));
' "${files[@]}"
