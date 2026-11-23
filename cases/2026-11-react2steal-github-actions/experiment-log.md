# Journal d'expériences

## Environnement

- Conteneur Docker construit depuis `lab/Dockerfile` : `node:22-bookworm-slim`, nginx (Debian 12), Next.js **15.2.2**, React **19.0.0**. Ces deux versions sont volontairement vulnérables à CVE-2025-29927 (corrigé en 15.2.3) et à CVE-2025-55182 (corrigé en 15.2.6 / React 19.0.1).
- Conteneur lancé avec `--network none` : aucune interface réseau hors boucle locale, aucun port publié sur l'hôte.
- Application minimale (`lab/app`) : un middleware qui redirige `/admin` vers `/login` sans cookie `session`, une page `/form` avec une Server Action, une image locale.
- nginx en frontal, deux serveurs : `:8080` sans filtrage, `:8081` qui retire `x-middleware-subrequest` (`proxy_set_header x-middleware-subrequest ""`). Deux formats de journal : `combined` (défaut) et un JSON enrichi des en-têtes utiles (`lab/nginx.conf`).
- Faux service de métadonnées AWS : `python3 -m http.server` lié à 169.254.169.254 (adresse ajoutée à `lo`, capacité `NET_ADMIN`), identifiants factices `FAKE-LAB-*`.
- **Aucune charge d'exploitation** n'est envoyée : seulement les en-têtes, chemins et boundary publiés par SRC-001, avec un corps multipart inerte (`a=1`).

## EXP-001 : forme du contournement CVE-2025-29927

Méthode : `GET /admin` sans cookie via `:8080`, cinq variantes (`lab/run-exp.sh`). Preuve : `evidence/lab-run-1.log`.

| Variante | Statut | Résultat |
|---|---|---|
| A. Requête normale | 307 | redirigée vers `/login` |
| B. En-tête envoyé **5 fois**, valeur `middleware` (lecture littérale de SRC-001) | 307 | **pas de contournement** |
| C. 1 en-tête, valeur `middleware` | 307 | pas de contournement |
| D. 1 en-tête, valeur `middleware:middleware:middleware:middleware:middleware` | **200** | **page admin servie** |
| E. Même chose avec `src/middleware` (mauvais chemin pour cette app) | 307 | pas de contournement |

Constat : il faut la valeur exacte du chemin du middleware, répétée cinq fois, dans un seul en-tête. Pour B, nginx ne journalise que `middleware` (la première valeur).

## EXP-002 : mitigation au proxy

La variante D via `:8081` renvoie 307. Le journal JSON du proxy enregistre quand même la valeur reçue : la tentative reste détectable après mitigation.

## EXP-003 : SSRF `/_next/image` vers les métadonnées cloud

Méthode : `lab/run-exp3.sh`, deux démarrages distincts (`LAB_IMAGES=default` puis `permissive` = `remotePatterns: [{protocol:'http', hostname:'**'}]`). Preuve : `evidence/lab-run-exp3.log`.

| Configuration | Réponse au client | Requêtes reçues par le faux IMDS | Journal Next.js |
|---|---|---|---|
| Par défaut | 400 `"url" parameter is not allowed` | **0** | rien |
| `remotePatterns` permissif | 400 `The requested resource isn't a valid image.` | **2** (liste des rôles, puis rôle) | `The requested resource isn't a valid image for http://169.254.169.254/... received text/html` |

Constat : en configuration permissive, la requête part bien vers le service de métadonnées (SSRF réelle côté réseau), mais Next.js 15.2.2 ne renvoie pas le contenu : SSRF aveugle. Limites : faux IMDS (types de contenu `text/html` et `application/octet-stream`, le vrai IMDS renvoie `text/plain`) ; une seule version de Next.js ; pas d'IMDSv2 testé (aucun environnement AWS).

**Erreur corrigée** : un premier passage, intégré à `run-exp.sh`, n'était pas valide. `pkill` étant absent de l'image, Next.js n'avait pas redémarré avec la configuration permissive (`EADDRINUSE`) : le test « permissif » tournait en réalité en configuration par défaut. EXP-003 a été sorti dans `run-exp3.sh`, qui lance un conteneur par configuration, et `lab-run-1.log` a été régénéré sans ce passage.

## EXP-004 : marqueurs de requête React2Shell

`POST /` avec `Next-Action: x`, `Content-Type: multipart/form-data; boundary=bissa_cve_boundary`, corps inerte ; variantes `x-action-id: x` et `Transfer-Encoding: chunked`. Les trois répondent **500**.

Journal `combined` par défaut : `"POST / HTTP/1.1" 500 87 "-" "curl/7.88.1"`, rien d'autre. Journal enrichi : `next_action":"x"` et la boundary sont visibles.

## EXP-005 : trafic légitime (base de faux positifs)

`lab/run-baseline.sh`, preuve `evidence/lab-baseline.log` : pages, `/admin` avec cookie, image locale via `/_next/image?url=%2Flogo.png` (200), appel de Server Action avec le vrai identifiant, soumission HTML pure.

- Identifiant d'action réel : `406bd75102012bd3eaee8894ca20ece52e3c2ee938`, **42 caractères hexadécimaux**.
- L'appel construit à la main avec ce vrai identifiant répond **500** (corps au mauvais format) : un 500 sur un POST avec `Next-Action` n'est donc pas discriminant.
- La soumission HTML pure n'envoie pas d'en-tête `Next-Action`.

## EXP-006 : exécution des règles Sigma

`sigma check` : 0 erreur. Conversion `sigma convert -t sqlite --without-pipeline`, requêtes exécutées par `detection/run-rules-on-lab-logs.py` sur une base SQLite chargée avec les journaux EXP-001 à EXP-005 (24 événements, dont 7 légitimes). Preuve : `evidence/sigma-sqlite-run.log`.

| Règle | Correspondances | Attendu |
|---|---|---|
| `web_nextjs_middleware_subrequest_external` | 5 (B, C, D, E, D via proxy filtrant) | toutes les tentatives, y compris ratées et mitigées |
| `web_nextjs_image_ssrf_cloud_metadata` | 4 | les 4 requêtes vers 169.254.169.254 (2 par configuration) |
| `web_nextjs_server_action_malformed_id` | 3 | I, J, K ; **pas** l'appel légitime à 42 caractères |
| `app_nextjs_image_optimizer_metadata_fetch` | 2 | les 2 messages Next.js de la configuration permissive |

0 correspondance sur les 7 événements légitimes. Échantillon petit : aucune mesure de faux positifs en production.

Note d'outillage : `pysigma-backend-sqlite` ne s'installe pas avec ses dépendances (compilation de `google-re2` impossible) ; installé avec `--no-deps`, la fonction `REGEXP` est fournie par le script Python.

## EXP-007 : script de vérification GitHub

`detection/check-react2steal-github.sh`, lancé depuis zsh. Preuve : `evidence/check-script-fixtures.log`.

- Dépôt factice « infecté » (fichiers vides aux noms des marqueurs, branches `wfx-docs` et `ci-sync-a1b2c3`, commit `w <w@w>` « chunk », workflow contenant le texte `toJSON(secrets)`) : 17 signalements, code de sortie 1.
- Dépôt sain : aucun signalement, code 0.
- Mode `--owner` sur un compte GitHub réel (23 dépôts) : aucun signalement. Chaque appel API contrôlé séparément sur un dépôt connu (arbre, branches, commits par auteur avec contrôle positif, PR) pour s'assurer que le « rien » ne vient pas d'erreurs masquées.

**Bug trouvé par le test positif** : la première version terminait par `… | tee /dev/stderr | grep -q '[!]' && …`. `grep -q` s'arrête au premier résultat, `tee` reçoit SIGPIPE et, avec `set -o pipefail`, le pipeline échoue : **le dépôt infecté était déclaré sain**. Corrigé en capturant la sortie dans une variable avant le test.

Limites : `--owner` non testé en positif (cela demanderait de créer un dépôt public piégé) ; un dépôt vide fait échouer l'appel d'arbre en silence ; le journal de sécurité du compte et les applications OAuth autorisées ne sont pas accessibles par cette API et restent à vérifier à la main.
