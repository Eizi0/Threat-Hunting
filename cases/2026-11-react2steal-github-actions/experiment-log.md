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

## EXP-008 : matrice de versions Next.js

Méthode : `lab/Dockerfile.matrix` (versions passées en argument de build) et `lab/run-matrix.sh`, chaque version lancée deux fois (`default` puis `permissive`), toujours `--network none`. Preuves : `evidence/matrix/<version>.log`. Pour chaque version : identifiant d'action dans le HTML et dans `.next/server/server-reference-manifest.json`, contournement CVE-2025-29927, réponse à `Next-Action` = `x` / faux identifiant hexadécimal de 42 caractères / vrai identifiant (corps multipart inerte, boundary `bissa_cve_boundary`), SSRF `/_next/image`.

| Version | ID d'action | 29927 (valeur ×5) | `x` | faux ID au bon format | vrai ID | SSRF défaut | SSRF permissif |
|---|---|---|---|---|---|---|---|
| 14.2.24 | 40 car. | **contourné** (200) | 500 | 500 | 500 | refusée, 0 req. | **1 req. IMDS**, aveugle |
| 15.2.2 | 42 car. | **contourné** (200) | 500 | 500 | 500 | refusée, 0 req. | **1 req. IMDS**, aveugle |
| 15.2.3 | 42 car. | bloqué (307) | 500 | 500 | 500 | refusée | **1 req. IMDS**, aveugle |
| 15.5.6 | 42 car. | bloqué | 500 | 500 | 500 | refusée | **1 req. IMDS**, aveugle |
| 15.5.7 | 42 car. | bloqué | 500 | 500 | 500 | refusée | **1 req. IMDS**, aveugle |
| 15.5.8 | 42 car. | bloqué | **404** | **404** | 500 | non testé | non testé |
| 15.5.9 | 42 car. | bloqué | **404** | **404** | 500 | non testé | non testé |
| 15.5.10 | 42 car. | bloqué | **404** | **404** | 500 | non testé | non testé |
| 15.5.29 | 42 car. | bloqué | **404** | **404** | 500 | refusée | **1 req. IMDS**, aveugle |
| 16.0.6 | 42 car. | bloqué | 500 | 500 | 500 | refusée | **bloquée** : `resolved to private ip` |
| 16.1.7 | 42 car. | bloqué | **404** | **404** | 500 | refusée | **bloquée** : `resolved to private ip` |

Constats :
1. Le manifeste de compilation contient exactement l'identifiant vu dans le HTML, sur toutes les versions.
2. Jusqu'à 15.5.7 et en 16.0.6, `x`, un faux identifiant et le vrai reçoivent **la même réponse** : aucune vérification de l'action avant le traitement du corps. Cela concorde avec Wiz et Trend Micro (« any Next-Action value… triggers the vulnerable code path »). Une règle sur le format de l'identifiant est donc contournable.
3. À partir de 15.5.8 (et en 16.1.7), un identifiant inconnu reçoit **404 « Server action not found »** et Next.js journalise `Failed to find Server Action "<id>"`. 15.5.29 journalise en plus `The Server Reference ID did not match the expected format` pour `x`. **15.5.7, pourtant premier correctif de CVE-2025-55182, se comporte encore comme les versions vulnérables** : le code 500 ne distingue pas un serveur vulnérable d'un serveur corrigé.
4. Le vrai identifiant répond 500 partout : le corps inerte envoyé n'est pas un appel valide. Ce 500 ne dit rien de l'exploitabilité.
5. SSRF : refusée en configuration par défaut partout ; avec `remotePatterns` permissif, la requête atteint le service de métadonnées en 14.2 et 15.x (réponse jamais renvoyée au client), mais est bloquée en 16.x avant tout envoi (`upstream image … resolved to private ip`).

Limites : 14.2.24 n'est pas concernée par CVE-2025-55182 d'après les avis, son comportement identique sur un corps inerte ne dit rien de son exploitabilité ; 15.5.8 à 15.5.10 testées seulement en `default` ; versions intermédiaires entre 15.5.10 et 15.5.29 non testées pour le message de format.

## EXP-009 : règle par liste d'identifiants du build

`detection/extract-nextjs-action-ids.sh` lit le manifeste du build et produit un pipeline pySigma (`value_placeholders`) ; la règle `web_nextjs_server_action_unknown_id` l'utilise via `next_action|expand: '%nextjs_action_ids%'`. Test sur le journal 15.5.6 (pipeline généré depuis le vrai build : `evidence/matrix/nextjs-action-ids-15.5.6.pipeline.yml`, preuve `evidence/matrix/sigma-action-id-15.5.6.log`) :

- règle par liste : 2 correspondances, `x` et le faux identifiant ; le vrai n'est pas signalé ;
- ancienne règle sur le format : sa partie « format » ne voit que `x` ; le faux identifiant n'est pris que par la sélection « boundary de campagne », qu'une variante de React2STEAL rend aléatoire. Elle est rétrogradée en indicateur de campagne (`level: medium`).

`app_nextjs_server_action_not_found` (journal applicatif), exécutée sur les journaux des 11 versions : 10 correspondances, exactement 2 par version de 15.5.8, 15.5.9, 15.5.10, 15.5.29 et 16.1.7 ; aucune sur 14.2.24, 15.2.2, 15.2.3, 15.5.6, 15.5.7, 16.0.6 (preuve `evidence/matrix/sigma-app-not-found.log`).

## EXP-010 : télémétrie hôte de la collecte (auditd + DNS)

Environnement : VM de labo Debian 12 (2 Go, processeur virtuel QEMU générique sans AVX), auditd, Node 22. Compte de service `labweb` ; application du labo en Next.js **15.5.6** (vulnérable) dans `/srv/r2s-app`, augmentée d'une route `lab-host/app-overlay/app/api/lab-sim/route.js`. Faux secrets : `.env`, `~labweb/.aws/credentials`, jeton Kubernetes factice. Trou noir DNS : `dnsmasq` (`lab-host/dnsmasq-r2s.conf`) qui répond 127.0.0.9 et ::1 pour les API d'IA, résolveur système pointé dessus pendant l'expérience. Règles auditd : `lab-host/audit.rules`. Script : `lab-host/run-host-exp.sh` ; analyse : `lab-host/analyze-audit.py`. Preuves : `evidence/host/`.

**Principe** : aucune exploitation. La route de labo exécute **dans le processus Next.js lui-même** (même PID, même exécutable, même utilisateur, en cours de vie du serveur) les comportements décrits pour `fast_recon.js` : lecture de `process.env`, des identifiants cloud, du jeton Kubernetes et des `.env`, inventaire de `/proc` et `/proc/net/tcp`, test d'écriture de répertoires, puis appel des API de 5 fournisseurs d'IA avec l'agent utilisateur Chrome 126 et une clé factice. C'est la télémétrie qu'une exécution de code réelle produirait pour ces actions ; la phase d'exploitation elle-même n'est pas reproduite.

Phases horodatées (`phases.txt`) : START (démarrage), BASELINE (pages, `/admin` avec cookie, soumission de la Server Action), SIMULATION (appel de la route), END.

| Phase | Lectures surveillées | Processus lancés (`execve`) | Connexions hors serveur | Requêtes DNS |
|---|---|---|---|---|
| START | `.env` ×1 (Next.js charge `.env` au démarrage) | 28 (enveloppes `nohup`/`npx`/`env`/`dash`, puis `node`) | 0 | 0 |
| BASELINE | 0 | 0 | 0 | 0 |
| SIMULATION | `.aws/credentials`, jeton Kubernetes, `.env` (2ᵉ lecture) | **0** | 27 `connect` : 127.0.0.1:53 puis 127.0.0.9:443 et [::1]:443 | 10 (A + AAAA pour 5 domaines) |

Constats :
1. **Aucun processus lancé pendant la collecte** : les règles « node lance un shell » (Elastic, DFIRtnt n°1, Sigma courantes) ne voient rien de ce type de charge, comme l'indiquait Wiz pour les charges « Node-native ».
2. **La lecture de l'environnement est invisible** : `process.env` est en mémoire (43 variables collectées, aucun appel système). C'est pourtant la source principale de secrets selon SRC-001.
3. Visibles : lecture des fichiers d'identifiants (surveillance de fichier), requêtes DNS vers les API d'IA, connexions sortantes de `node` vers le port 443.
4. `.env` est lu légitimement au démarrage : une règle « node lit .env » est bruyante ; c'est une **seconde lecture en cours de vie** qui est anormale (non exprimable simplement en Sigma, laissée en piste de chasse).
5. Le titre de processus `next-server (v15.5.6)` apparaît dans les `PROCTITLE` d'auditd : utile pour inventorier les versions.

Règles exécutées (SQLite, `detection/run-rules-on-host-logs.py`, preuve `evidence/host/sigma-host-run.log`, 69 événements) :
- `lnx_auditd_node_reads_cloud_credentials` : 2 correspondances (identifiants AWS, jeton Kubernetes), toutes en SIMULATION ;
- `dns_webserver_ai_api_query` : 10 correspondances, toutes en SIMULATION (aucune autre requête DNS pendant l'expérience).

**Incidents et erreurs pendant la mise au point (tous corrigés, consignés pour transparence)** :
- `next build` puis `next start` plantaient en « Bus error » : le binaire natif SWC (`@next/swc-linux-x64-gnu`) et `sharp` ne supportent pas le processeur virtuel QEMU générique de la VM. Build fait dans Docker (même base Debian 12, amd64) et copié ; SWC natif retiré pour le repli WebAssembly ; requête d'image retirée de la base VM.
- `auditctl -R` ne chargeait **aucune** règle sans message d'erreur (fichier avec commentaires accentués) : chargement ligne par ligne, vérifié par `audit-rules-loaded.txt`.
- `pkill -f "next start"` ne trouve pas le serveur, qui se renomme `next-server` ; et un `pkill -f "npm install"` a tué ma propre session SSH (motif présent dans sa ligne de commande).
- **Un essai a envoyé des requêtes réelles vers l'extérieur** : un test rapide de la route, lancé alors que le résolveur avait été restauré, a appelé les 5 API d'IA réelles avec la clé `FAKE-LAB-KEY` (réponses 401, aucun vrai secret). Garde-fou ajouté à la route (refus en 503 si le résolveur n'est pas le trou noir local), testé.
- **Trou noir IPv6 absent au premier passage** : seules les réponses A étaient détournées ; les AAAA partaient à l'amont et `node` a tenté 13 connexions IPv6 vers les vraies adresses, toutes en échec `ENETUNREACH` (pas de route IPv6 sur la VM, vérifié dans les `SYSCALL` : `success=no exit=-101`). Réponses `::1` ajoutées ; passage final : 0 requête transmise à l'amont.

Limites : une seule version (15.5.6), base légitime courte, un seul serveur ; pas de vraie exploitation (la phase d'exécution de code initiale n'est pas observée) ; surveillance de `/proc` non posée ; journal DNS sans attribution au processus (la corrélation se fait par `connect` auditd).

## EXP-011 : résistance aux variations (évasion)

Méthode : `lab/run-variants.sh` sur 15.2.2, 15.5.6 et 16.1.7, configurations `default` et `permissive`, toujours `--network none`. Ajouts dans le conteneur : un hôte « autorisé » (127.0.0.5) qui répond par une redirection 302 vers le service de métadonnées, et un nom `imds-alias.lab` qui résout vers 169.254.169.254 (`/etc/hosts`). Preuves : `evidence/variants/`.

SSRF (7 variantes × 3 versions × 2 configurations) :

| Variante | Atteint le service (14/15 permissif) | 16.x permissif | Règle URL avant durcissement | Règle URL après | Règle applicative 14/15 | Règle applicative 16.x |
|---|---|---|---|---|---|---|
| adresse directe | oui | bloquée | ✓ | ✓ | ✓ | ✓ |
| décimale `2852039166` | oui | bloquée | ✗ | ✓ | ✓ (Next.js normalise) | ✓ |
| hexadécimale `0xa9fea9fe` | oui | bloquée | ✗ | ✓ | ✓ (normalisée) | ✓ |
| IPv6 mappée | oui | bloquée | ✓ | ✓ | ✓ (après ajout de `a9fe:a9fe`) | ✓ |
| URL entièrement encodée | oui | bloquée | ✗ | ✓ | ✓ | ✓ |
| nom DNS vers 169.254.169.254 | oui | bloquée | ✗ | **✗** | **✗** | ✓ |
| redirection depuis un hôte autorisé | oui | bloquée | ✗ | **✗** | **✗** | ✓ |

En configuration par défaut, toutes les variantes sont refusées (400) sur les trois versions. Exécution SQLite : `evidence/variants/sigma-variants-run.log`.

Next-Action (configuration par défaut) : `NEXT-ACTION` (casse) est traité comme `Next-Action` ; `rsc-action-id: x` n'est pas traité comme une action par Next.js (200 HTML en 15.x) ; un **vrai identifiant lu dans le HTML de la page** reçoit la même réponse que `x` sur les versions vulnérables : la règle par liste du build ne le voit pas. En 16.1.7, un POST multipart sans en-tête d'action reçoit 500 et le journal `Failed to find Server Action.`

Middleware (15.2.2 vulnérable) : une valeur préfixée `foo:middleware:…` (×5) **contourne** ; la casse du nom d'en-tête ne change rien (contournement) ; des espaces autour des `:` empêchent le contournement ; une sonde `x` ne contourne rien mais échappait à la règle (qui cherchait `middleware`).

Modifications des règles qui en découlent : middleware → toute valeur non vide ; URL SSRF → formes décimale, hexadécimale, IPv6 mappée et encodée ; applicative SSRF → `a9fe:a9fe` ; nouvelle règle `app_nextjs_image_private_ip_blocked` (16.x). Non-régression rejouée sur le jeu initial : mêmes résultats (`evidence/sigma-sqlite-run.log`).

## EXP-012 : trafic réel (journal Traefik du serveur du blog)

Jeu : journal d'accès JSON de Traefik d'un serveur personnel exposé (site statique, pas de Next.js), **777 087 requêtes du 18/12/2025 au 23/11/2026**. Analyse faite sur le serveur, seuls des agrégats sont sortis (aucune adresse IP, aucun hôte). Les en-têtes de requête ne sont pas journalisés : seules les règles fondées sur l'URL sont applicables.

- Règle `web_nextjs_image_ssrf_cloud_metadata` : **0 correspondance** (ni vrai ni faux positif). 8 requêtes `/_next/image?url=` vues, toutes vers des chemins relatifs (404/301).
- 102 clients distincts ont sondé des chemins `/_next/` (site sans Next.js) : `/_next/server`, `/_next/../.env`, `/_next/static/…/.env`, `/_next/../.aws/credentials`, `/_next/../.azure/credentials`, `/_next/data/*/…json`, `main.js.map`.
- 2 244 requêtes portent une adresse de métadonnées **hors** de `/_next/image` (21 clients, surtout août-septembre 2026) : paramètres génériques `/fetch?url=`, `/proxy?url=`, `/api/fetch?url=`, `/webhook?url=`, `/redirect?url=`… Statuts : 1 613 × 404, 615 × 301, **16 × 200**.
- Les 16 réponses 200 sont toutes la **page d'accueil** (`/`, 5 992 octets) servie avec un paramètre ignoré : un statut 200 sur une requête d'attaque ne prouve pas son succès.
- POST par mois : de 700 à 4 583, sans pic exploitable en décembre 2025 (journal commencé le 18/12).

## EXP-013 : backends Sigma, Wazuh et corrélation

Conversion des 9 règles (pySigma) vers Splunk, Elasticsearch Lucene, ES|QL, Loki et SQLite : **9/9 sans erreur pour chaque backend** (`evidence/backends/`). C'est une compatibilité de syntaxe : seule l'exécution SQLite est réellement testée, et les noms de champs devront être adaptés au modèle de chaque SIEM. Piège : sous zsh, un tableau d'options passé dans une variable non découpée faisait échouer la conversion avec un message trompeur (« pipeline not found »).

**Wazuh** : pas de backend Sigma officiel. Traduction manuelle en `detection/wazuh/react2steal_rules.xml` (+ décodeurs dnsmasq et Next.js), validée par `wazuh-analysisd -t` puis **exécutée** dans `wazuh/wazuh-manager:4.12.0` (conteneur sans réseau) via le socket `wazuh-logtest` (`detection/wazuh/run-logtest.py`). Jeu : 199 événements étiquetés construits depuis les preuves (`detection/wazuh/build-input.py`) ; vérité terrain = origine de la requête (sonde du labo ou trafic légitime), pas la règle testée. Preuve : `evidence/wazuh-logtest-run.log`.

| Source | VP | FN | FP | VN | Hors périmètre |
|---|---|---|---|---|---|
| web (proxy) | 65 | 20 | 1 | 11 | — |
| application | 24 | 2 | 0 | — | 7 (lignes de continuation, « Connection closed ») |
| auditd | 2 | 0 | 0 | 57 | — |
| DNS | 10 | 0 | 0 | — | — |

- FN web : nom DNS et redirection (12, attendus), POST sans `Next-Action` (6, sondes qui n'atteignent pas le traitement d'action en 15.x), vrai identifiant (2, attendu).
- FP web : l'appel légitime de la base, fait sur un build **15.2.2**, est signalé car la liste Wazuh contient l'identifiant du build **15.5.6** : c'est le problème d'association événement ↔ manifeste (voir EXP-014).
- FN application : nom DNS et redirection en 15.x (attendus).
- **Corrélation** (règle 100740, `if_sid` DNS + `if_matched_sid` lecture d'identifiants, fenêtre 300 s) : dans la session complète, les 10 requêtes DNS qui suivent la lecture d'identifiants montent au niveau 14 ; dans une session témoin contenant seulement les requêtes DNS, elles restent au niveau 7 (règle 100730). Limite : en production, la corrélation suppose que l'auditd et le DNS remontent du même agent ; avec un résolveur central, il faut une clé commune (adresse source).
- Erreurs de mise au point corrigées : la règle de niveau 0 qui reconnaît le format JSON était comptée comme alerte ; les lignes dnsmasq sans nom d'hôte n'étaient pas décodées (le format syslog réel l'inclut) ; étiquetage initial qui classait des sondes comme légitimes d'après la règle testée.

## EXP-014 : liste d'identifiants et déploiement progressif

`extract-nextjs-action-ids.sh` accepte désormais plusieurs builds (union, chaque identifiant annoté de son `BUILD_ID`). Test avec les manifestes réels des builds 15.5.6 (`401f9e…`) et 15.5.7 (`40ffdd…`) sur les journaux des deux versions (`evidence/matrix/sigma-rolling-deploy.log`) :

- liste du seul build 1 : le **vrai** identifiant du build 2 est signalé à tort (faux positif de déploiement progressif) ;
- union des deux builds : plus de faux positif ; `x` et les faux identifiants restent détectés.

Pistes d'industrialisation (non testées) : journaliser l'instance amont (`$upstream_addr` sous nginx) pour associer chaque requête au manifeste de l'instance qui l'a traitée ; ou configurer `deploymentId` dans Next.js et journaliser l'en-tête de version envoyé par le client ; générer la liste dans la chaîne de déploiement et la publier vers le SIEM avec l'artefact.
