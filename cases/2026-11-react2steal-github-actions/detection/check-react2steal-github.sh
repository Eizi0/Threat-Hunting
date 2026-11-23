#!/usr/bin/env bash
# Recherche, en LECTURE SEULE, les marqueurs publiés de React2STEAL et de wfx-loot.
#   Compte/organisation : ./check-react2steal-github.sh --owner <compte>      (nécessite gh authentifié)
#   Clone local         : ./check-react2steal-github.sh --local <chemin-du-clone>
# Aucun résultat ne prouve l'absence de compromission : les marqueurs peuvent avoir été supprimés.
set -uo pipefail
FILES_RE='(^|/)(bin/batch_output\.py|bin/prefilter_nextjs\.py|bin/fast_recon\.js|docs/wfx-audit\.md)$|^vulnerables/'
BRANCH_RE='^(wfx-docs|ci-sync-[A-Za-z0-9]{6})$'
MSG_RE='^(chunk|results [0-9]{10}|docs: add dependency audit notes|ci: refresh build cache|ci: restore|ci: sync config)$'
flag(){ echo "  [!] $*"; }

check_local(){
  local d=$1; echo "== clone local : $d"
  git -C "$d" rev-parse --git-dir >/dev/null 2>&1 || { echo "  pas un dépôt git"; return 1; }
  git -C "$d" for-each-ref --format='%(refname:short)' refs/heads refs/remotes | sed 's#^origin/##' | grep -E "$BRANCH_RE" | sort -u | while read -r b; do echo "  [!] branche suspecte : $b"; done
  while read -r b; do
    git -C "$d" ls-tree -r --name-only "$b" 2>/dev/null | grep -E "$FILES_RE" | sed "s#^#  [!] fichier marqueur ($b) : #"
  done < <(git -C "$d" for-each-ref --format='%(refname)' refs/heads refs/remotes)
  git -C "$d" log --all --format='%h %ae %s' | awk '$2=="w@w"' | head -5 | sed 's#^#  [!] commit auteur w@w : #'
  git -C "$d" log --all --format='%h %s' | while read -r h s; do [[ $s =~ $MSG_RE ]] && echo "  [!] message de commit marqueur : $h $s"; done | head -10
  git -C "$d" grep -l -E 'toJSON\(secrets\)' $(git -C "$d" for-each-ref --format='%(refname)' refs/heads refs/remotes) -- '.github/workflows/*' 2>/dev/null | sed 's#^#  [!] workflow qui sérialise tous les secrets : #'
}

check_owner(){
  local o=$1; echo "== compte GitHub : $o"
  local repos; repos=$(gh repo list "$o" --limit 1000 --json name --jq '.[].name') || { echo "  gh a échoué"; return 1; }
  echo "  $(echo "$repos" | grep -c .) dépôts examinés"
  for r in $repos; do
    [[ $r =~ ^ci-wk-[0-9]+$ ]] && flag "$o/$r : nom au format ci-wk-<n>"
    gh api "repos/$o/$r/branches?per_page=100" --paginate --jq '.[].name' 2>/dev/null | grep -E "$BRANCH_RE" | while read -r b; do echo "  [!] $o/$r : branche $b"; done
    gh api "repos/$o/$r/git/trees/HEAD?recursive=1" --jq '.tree[].path' 2>/dev/null | grep -E "$FILES_RE" | while read -r p; do echo "  [!] $o/$r : fichier $p"; done
    gh api "repos/$o/$r/commits?author=w@w&per_page=5" --jq '.[].sha[0:7]' 2>/dev/null | while read -r s; do echo "  [!] $o/$r : commit de w@w $s"; done
    gh api "repos/$o/$r/pulls?state=all&per_page=100" --jq '.[] | select(.title=="docs: dependency audit notes" or .head.ref=="wfx-docs") | "#\(.number) \(.title)"' 2>/dev/null | while read -r p; do echo "  [!] $o/$r : PR $p"; done
  done
  echo "  Rappel : vérifier aussi à la main le journal de sécurité du compte (Settings > Security log) et les jetons/OAuth apps autorisés."
}

case "${1:-}" in
  --local) out=$(check_local "${2:?chemin}") ;;
  --owner) out=$(check_owner "${2:?compte}") ;;
  *) sed -n '2,6p' "$0"; exit 2 ;;
esac
echo "$out"
# Pas de « | grep -q » derrière un tee : avec pipefail, le SIGPIPE faisait passer un dépôt compromis pour sain.
if grep -q '\[!\]' <<<"$out"; then
  echo "RÉSULTAT : marqueur(s) trouvé(s), traiter le compte comme compromis (révoquer jetons et grants, faire tourner les secrets)"; exit 1
fi
echo "RÉSULTAT : aucun marqueur trouvé (ce n'est pas une preuve d'absence de compromission)"
