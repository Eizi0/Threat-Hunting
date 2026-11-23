# Registre des affirmations

Dernière mise à jour : 2026-11-23. Statut de preuve : **A** incident rapporté · **B** analyse statique tierce · **C** vérifié en laboratoire · **D** déduit.

| # | Affirmation | Sources | Statut | Formulation autorisée |
|---|---|---|---|---|
| C1 | Des dépôts GitHub publics `ci-wk-<n>` exécutent un scanner via un workflow `workflow_dispatch` (`scan.yml`) sur des runners hébergés, et poussent les résultats dans le même dépôt | SRC-001 | B (code lu par SRC-001) | « selon OpenSourceMalware » |
| C2 | 45 dépôts, 44 comptes, trois vagues (22/10, 11/11, 14/11/2026) ; au moins 1 281 noms d'hôtes victimes | SRC-001 | B, plancher déclaré | « au moins », chiffres de SRC-001 |
| C3 | Chiffres initiaux de Karina Reaño : 38 dépôts, > 20 000 hôtes ciblés, ~277 compromis | SRC-001 | A (détermination d'un tiers) | L'attribuer à elle |
| C4 | Les données volées (variables d'environnement, fichiers `.env`, identifiants cloud, clés d'IA) sont lisibles publiquement | SRC-001 | B | OK |
| C5 | Le scanner exploite CVE-2025-55182 (7 variantes, `Next-Action: x`, boundary `bissa_cve_boundary`) puis CVE-2025-29927, puis une SSRF `/_next/image` vers 169.254.169.254 | SRC-001 | B | OK |
| C6 | L'article dit « en-tête `x-middleware-subrequest` répété cinq fois » | SRC-001 | Formulation ambiguë | Citer et préciser |
| C7 | Le contournement efficace = **un** en-tête dont la **valeur** répète cinq fois le nom du middleware ; l'en-tête envoyé cinq fois ne contourne pas | SRC-002, SRC-004 ; EXP-001 | **C** (Next.js 15.2.2) | OK, préciser la version |
| C8 | Retirer l'en-tête au proxy bloque le contournement, et la tentative reste journalisée par le proxy | SRC-002 ; EXP-002 | **C** | OK |
| C9 | En configuration par défaut, `/_next/image` refuse une URL vers 169.254.169.254 (400) et aucune requête n'atteint le service de métadonnées | EXP-003 | **C** (15.2.2) | Ne pas généraliser à toutes les versions |
| C10 | Avec `remotePatterns` permissif, le serveur interroge le service de métadonnées mais ne renvoie pas le contenu (pas une image) : SSRF aveugle | EXP-003 | **C** (15.2.2, faux IMDS) | « dans mon laboratoire » ; ne pas affirmer que la SSRF ne marche jamais (autres versions/configurations non testées) |
| C11 | L'optimiseur laisse un message explicite dans le journal de Next.js quand la requête est partie | EXP-003 | **C** | OK |
| C12 | Le format de journal nginx par défaut ne montre ni `x-middleware-subrequest`, ni `Next-Action`, ni la boundary : contournement = `GET /admin 200`, tentative RCE = `POST / 500` | EXP-001, EXP-004 | **C** | OK |
| C13 | Un identifiant d'action légitime fait 40 caractères hexadécimaux en 14.2.24, 42 en 15.x/16.x ; il figure dans `server-reference-manifest.json` ; une Server Action légitime peut aussi répondre 500 | EXP-005, EXP-008 | **C** | Préciser les versions |
| C14 | Sur les jeux du labo, les règles détectent les tentatives visées ; mesures VP/FN/FP détaillées par source dans EXP-011 et EXP-013 | EXP-006, EXP-011, EXP-013 | **C** (jeux de labo, petit volume légitime) | Ne pas parler de taux de faux positifs en production ; citer les FN connus |
| C15 | Le script de vérification GitHub signale les marqueurs sur un dépôt factice et rien sur un dépôt sain ou un compte réel | EXP-007 | **C** | Mode `--owner` non testé en positif |
| C16 | Qui opère la campagne, comment les jetons des 44 comptes ont été obtenus | SRC-001 | **Inconnu** (SRC-001 le dit) | « non établi » |
| C17 | Lien React2STEAL / wfx-loot : comptes partagés, pas de code ni d'infrastructure commune trouvés | SRC-001 | B | Ne pas fusionner les deux |
| C18 | Le principal chemin de vol est l'exécution de code (fast_recon.js lit l'environnement du processus), la SSRF n'en est qu'un complément | SRC-001 ; C10 ; EXP-008 (SSRF aveugle ou bloquée partout) | **D** renforcé | « je pense » |
| C19 | Sur une version vulnérable, n'importe quelle valeur de Next-Action atteint le traitement : `x`, un faux identifiant au bon format et le vrai reçoivent la même réponse | SRC-009, SRC-010 ; EXP-008 (14.2.24, 15.2.x, 15.5.6, 15.5.7, 16.0.6) | **C** | Une règle sur le format est contournable |
| C20 | À partir de 15.5.8 (et en 16.1.7), un identifiant inconnu reçoit 404 et Next.js journalise « Failed to find Server Action » ; 15.5.7, premier correctif, répond encore 500 | EXP-008 | **C** | Le 500 ne distingue pas vulnérable et corrigé |
| C21 | En 16.x, la SSRF est bloquée avant envoi même avec remotePatterns permissif (« resolved to private ip ») | EXP-008 | **C** (16.0.6, 16.1.7) | OK |
| C22 | La collecte dans le processus Node.js ne lance aucun processus ; la lecture de process.env est invisible ; les lectures d'identifiants et les requêtes DNS vers les API d'IA sont visibles | SRC-009 ; EXP-010 | **C** (simulation dans le processus, pas d'exploitation réelle) | « en simulant la collecte » |
| C23 | Next.js lit `.env` au démarrage : une règle « node lit .env » est bruyante | EXP-010 | **C** | OK |
| C24 | Aucun éditeur d'hébergement lu ne publie de signature React2Shell précise ; les règles publiques reposent sur l'en-tête Next-Action, le corps (motifs Flight) ou le lancement de processus | SRC-011 à SRC-014 | B | OK |
| C25 | « Un 200 sur une route protégée = contournement » est faux en général : un 200 peut venir d'une page de connexion, d'une réécriture, d'un cache ; en trafic réel, 16 requêtes de SSRF ont reçu 200 = page d'accueil d'un site statique | EXP-001 (contenu vérifié en labo), EXP-012 | **C** | « en labo, contenu vérifié » ; en production, comparer contenu/taille |
| C26 | En configuration permissive (14/15), 7 variantes de SSRF sur 7 atteignent le service de métadonnées ; nom DNS et redirection échappent aux règles fondées sur l'URL et au message applicatif 14/15 ; 16.x les bloque toutes et les journalise | EXP-011 | **C** (faux IMDS, 3 versions) | « dans les versions et configurations testées » |
| C27 | Un vrai identifiant d'action, lisible dans le HTML, contourne la règle par liste du build sur une version vulnérable | EXP-011 | **C** | OK |
| C28 | Sur 777 087 requêtes réelles (site statique), la règle SSRF fondée sur l'URL ne s'est pas déclenchée ; 102 clients ont sondé des chemins Next.js | EXP-012 | **C** (un seul serveur, pas de Next.js, en-têtes non journalisés) | OK, avec ces limites |
| C29 | Les 9 règles se convertissent sans erreur vers Splunk, Lucene, ES|QL, Loki ; traduction Wazuh exécutée dans wazuh-logtest avec corrélation fonctionnelle (témoin négatif inclus) | EXP-013 | **C** (syntaxe pour 4 backends, exécution pour SQLite et Wazuh) | Préciser syntaxe vs exécution |
| C30 | La règle par liste du build produit des faux positifs si l'événement est comparé au mauvais build ; l'union des builds en service les supprime | EXP-013, EXP-014 | **C** | Industrialisation (association par instance) non testée |
| C31 | Les constats « aucun processus enfant » et « process.env invisible » valent pour la collecte simulée de type fast_recon.js, pas pour toutes les exploitations de React2Shell (d'autres campagnes lancent des shells, cf. SRC-009, SRC-010) | EXP-010, SRC-009, SRC-010 | **C** (portée limitée) | Toujours préciser « dans ma simulation » |
