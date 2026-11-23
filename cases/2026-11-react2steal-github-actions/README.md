# React2STEAL : un scanner hébergé sur GitHub Actions qui vole des secrets Next.js

Cas lié à l'article [React2STEAL : quand GitHub Actions scanne Internet et publie le butin](https://www.jeovany.com/blog/react2steal-github-actions-nextjs/).

Analyse de la campagne décrite par OpenSourceMalware le 18 novembre 2026 : des dizaines de dépôts GitHub publics exécutent un scanner sur les runners GitHub, exploitent CVE-2025-55182 (React2Shell) et CVE-2025-29927 sur des applications Next.js, puis publient les secrets volés dans ces mêmes dépôts.

## Ce que contient ce dossier

- `sources.md` : sources lues, ce qui n'a pas été lu et pourquoi (les dépôts de la campagne n'ont pas été consultés)
- `claims.md` : affirmations et niveau de preuve
- `experiment-log.md` : 10 expériences (labo Docker isolé, matrice de 11 versions de Next.js, télémétrie hôte auditd + DNS sur VM)
- `lab/` : laboratoire Docker (Dockerfile, `Dockerfile.matrix` pour les versions, application minimale, nginx, scripts). Aucune charge d'exploitation.
- `lab-host/` : laboratoire hôte (route de simulation de la collecte, règles auditd, trou noir DNS, script et analyseur)
- `detection/` : 8 règles Sigma exécutées sur les journaux du labo, le générateur de liste d'identifiants d'action, les exécuteurs SQLite, un script de vérification GitHub en lecture seule
- `evidence/` : journaux bruts du labo, indicateurs

## Résultats principaux

1. Le contournement CVE-2025-29927 passe par **un** en-tête dont la valeur répète cinq fois le nom du middleware ; l'en-tête envoyé cinq fois ne contourne rien. Une règle écrite au pied de la lettre de l'avis de campagne serait fragile.
2. Avec le journal nginx par défaut, une attaque réussie ressemble à `GET /admin 200` et une tentative React2Shell à `POST / 500`. Il faut journaliser trois en-têtes pour voir quelque chose.
3. La SSRF vers les métadonnées cloud échoue en configuration par défaut sur toutes les versions testées, reste aveugle en 14.2/15.x avec une configuration permissive (trace explicite dans le journal de l'application), et est bloquée en 16.x.
4. Sur une version vulnérable, n'importe quelle valeur de `Next-Action` est traitée : une règle sur le format de l'identifiant est contournable. La comparaison à la liste des identifiants du build (manifeste) ne l'est pas.
5. À partir de 15.5.8, un identifiant inconnu reçoit 404 et un message explicite ; 15.5.7, premier correctif, répond encore 500 comme les versions vulnérables.
6. La collecte dans le processus Node.js ne lance aucun processus et la lecture de l'environnement est invisible : seules les lectures de fichiers d'identifiants et les requêtes DNS vers les API d'IA se voient.
7. Le test positif du script de vérification a révélé un bug (`pipefail` + `grep -q`) qui faisait passer un dépôt compromis pour sain.

## Limites

Faux service de métadonnées, pas d'IMDSv2, pas de vraie exploitation (la collecte est simulée dans le processus), petits échantillons de trafic légitime, mode `--owner` du script non testé en positif. Erreurs et incidents de mise au point consignés dans `experiment-log.md`.

## Reproduire le labo

```bash
cd lab
docker build -t r2s-lab .
docker run --rm --network none --cap-add NET_ADMIN -v "$PWD/run-exp.sh:/run-exp.sh:ro" r2s-lab /run-exp.sh
for m in default permissive; do docker run --rm --network none --cap-add NET_ADMIN -v "$PWD/run-exp3.sh:/run-exp3.sh:ro" r2s-lab /run-exp3.sh $m; done
docker run --rm --network none -v "$PWD/run-baseline.sh:/r.sh:ro" r2s-lab /r.sh
```
