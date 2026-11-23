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
| C14 | Les 4 règles Sigma détectent toutes les tentatives du labo et aucun événement légitime | EXP-006 | **C** (petit échantillon : 7 événements légitimes) | Ne pas parler de taux de faux positifs en production |
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
