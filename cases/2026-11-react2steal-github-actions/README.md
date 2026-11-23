# React2STEAL : un scanner hébergé sur GitHub Actions qui vole des secrets Next.js

Cas lié à l'article [React2STEAL : quand GitHub Actions scanne Internet et publie le butin](https://www.jeovany.com/blog/react2steal-github-actions-nextjs/).

Analyse de la campagne décrite par OpenSourceMalware le 18 novembre 2026 : des dizaines de dépôts GitHub publics exécutent un scanner sur les runners GitHub, exploitent CVE-2025-55182 (React2Shell) et CVE-2025-29927 sur des applications Next.js, puis publient les secrets volés dans ces mêmes dépôts.

## Ce que contient ce dossier

- `sources.md` : sources lues, ce qui n'a pas été lu et pourquoi (les dépôts de la campagne n'ont pas été consultés)
- `claims.md` : affirmations et niveau de preuve
- `experiment-log.md` : laboratoire Next.js 15.2.2 isolé (sans réseau), 7 expériences
- `lab/` : de quoi reproduire le laboratoire (Dockerfile, application minimale, configuration nginx, scripts). Aucune charge d'exploitation.
- `detection/` : 4 règles Sigma exécutées sur les journaux du labo, l'exécuteur SQLite, un script de vérification GitHub en lecture seule
- `evidence/` : journaux bruts du labo, indicateurs

## Résultats principaux

1. Le contournement CVE-2025-29927 passe par **un** en-tête dont la valeur répète cinq fois le nom du middleware ; l'en-tête envoyé cinq fois ne contourne rien. Une règle écrite au pied de la lettre de l'avis de campagne serait fragile.
2. Avec le journal nginx par défaut, une attaque réussie ressemble à `GET /admin 200` et une tentative React2Shell à `POST / 500`. Il faut journaliser trois en-têtes pour voir quelque chose.
3. Sur Next.js 15.2.2, la SSRF vers les métadonnées cloud échoue en configuration par défaut et reste aveugle avec une configuration permissive, mais laisse une trace explicite dans le journal de l'application.
4. Le test positif du script de vérification a révélé un bug (`pipefail` + `grep -q`) qui faisait passer un dépôt compromis pour sain.

## Limites

Une seule version de Next.js, faux service de métadonnées, pas d'IMDSv2, petit échantillon de trafic légitime, mode `--owner` du script non testé en positif. Voir `experiment-log.md`.

## Reproduire le labo

```bash
cd lab
docker build -t r2s-lab .
docker run --rm --network none --cap-add NET_ADMIN -v "$PWD/run-exp.sh:/run-exp.sh:ro" r2s-lab /run-exp.sh
for m in default permissive; do docker run --rm --network none --cap-add NET_ADMIN -v "$PWD/run-exp3.sh:/run-exp3.sh:ro" r2s-lab /run-exp3.sh $m; done
docker run --rm --network none -v "$PWD/run-baseline.sh:/r.sh:ro" r2s-lab /r.sh
```
