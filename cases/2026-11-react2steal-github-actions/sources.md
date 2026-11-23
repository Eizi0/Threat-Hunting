# Sources

Dernière mise à jour : 2026-11-23. Chaque source a été lue séparément et identifiée par son titre, son auteur et sa date (pas par l'ordre des réponses).

| # | Source | Type | Lue | Fiabilité / remarques |
|---|---|---|---|---|
| SRC-001 | OpenSourceMalware, « React2STEAL Uses GitHub Actions to Exploit React2Shell », 2026-11-18, https://opensourcemalware.com/blog/react2steal-github-actions | Analyse primaire de la campagne | Oui, page complète | Seule source sur la campagne. Recherche initiée par Karina Reaño (CTI Lead), reprise et étendue par OpenSourceMalware. Auteur non nommé (identifiant de signature uniquement). Distingue bien ce qui est établi de ce qui ne l'est pas. |
| SRC-002 | Vercel / Next.js, GHSA-f82v-jwr5-mffw « Authorization Bypass in Next.js Middleware », 2025-03-21 | Avis de sécurité éditeur | Oui | Référence pour versions affectées/corrigées et contournement. CVSS 9.1. |
| SRC-003 | Vercel, « Postmortem on Next.js Middleware bypass », Ty Sbano, 2025-03-25 | Post-mortem éditeur | Oui | Auto-hébergé (`next start`, `standalone`) touché ; hébergé chez Vercel non touché. |
| SRC-004 | Rachid Allam (zhero) et Yasser Allam (inzo_), « Next.js and the corrupt middleware: the authorizing artifact », mars 2025 | Recherche d'origine | Oui | Donne le format exact de la valeur : `middleware:middleware:middleware:middleware:middleware` (versions récentes). |
| SRC-005 | React Team, « Critical Security Vulnerability in React Server Components », 2025-12-03 (mise à jour 2026-01-26) | Avis éditeur | Oui | CVE-2025-55182, CVSS 10.0, pré-authentification, versions 19.0.0, 19.1.0, 19.1.1, 19.2.0 ; corrigé en 19.0.1, 19.1.2, 19.2.1. |
| SRC-006 | Vercel / Next.js, GHSA-9qr9-h5gf-34mp « RCE in React Server Components », 2025-12-03 | Avis éditeur | Oui | Next.js ≥ 14.3.0-canary.77, 15.x, 16.x (App Router) ; correctifs 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7. |
| SRC-007 | Next.js, « Security Advisory: CVE-2025-66478 », 2025-12-03 (addenda 2025-12-06) | Avis éditeur | Oui | « Il n'y a pas de contournement, la mise à jour est obligatoire. » Pages Router et Edge Runtime non concernés. Recommande de faire tourner les secrets. |
| SRC-008 | Laboratoire (voir `experiment-log.md`) | Expérience propre | — | Niveau C. |
| SRC-009 | Wiz (Tamari, Tikochinski, Ramati, Read), « React2Shell Deep Dive: CVE-2025-55182 Exploit Mechanics », 2025-12-08 (mise à jour 2025-12-17) | Analyse technique + observations | Oui | « all payloads sent with this header are parsed » ; charges « Node-native » sans processus enfant qui contournent les règles de lancement de processus. |
| SRC-010 | Trend Micro (Girnus et al.), « CVE-2025-55182: React2Shell Analysis, Proof-of-Concept Chaos, and In-the-Wild Exploitation », 2025-12-10 | Analyse + campagnes | Partiellement (≈ 40 000 premiers caractères verbatim, le reste résumé) | « Setting any Next-Action header value (even Next-Action: foo) triggers the vulnerable code path ». |
| SRC-011 | Elastic, règle « React2Shell (CVE-2025-55182) Exploitation Attempt », version 2 | Règle de détection | Oui | Repose sur le corps de requête et le corps de réponse (`E{"digest"`) : capture réseau nécessaire. |
| SRC-012 | CrowdSec (Prin-Abeil), « React2Shell: The Overly Spicy Side of React 19 », 2026-01-21 | Patch virtuel WAF | Oui | POST + `next-action`/`rsc-action-id` + champs Flight `status`/`resolved_model`, motif `$@`. |
| SRC-013 | DFIRtnt (Skatoff), « React2Shell Exploits: High-Value Detection and Threat Hunting Strategies », 2025-12-05 (mise à jour 2026-02-23) | Idées de règles | Oui | 7 pistes (lancement de shell par node, lecture /etc/passwd, POST avec next-action, 500, sortie de node vers IP nues). |
| SRC-014 | Vercel, « React2Shell Security Bulletin » et « Summary of CVE-2025-55182 », décembre 2025 | Bulletin éditeur | Oui | Aucune signature publiée ; « WAF rules cannot guarantee protection against all possible variants ». |

## Non lu / non utilisé

- Pages NVD de CVE-2025-29927 et CVE-2025-55182 : HTTP 200 mais contenu rendu côté client, rien d'exploitable. Scores repris des avis éditeurs, pas de NVD.
- Billet AWS « China-nexus cyber threat groups rapidly exploit React2Shell » : HTTP 200 mais corps non récupéré (navigation seule) ; contenu connu seulement par SRC-013.
- Cloudflare, Akamai, Fastly, Google Cloud, Netlify : pages d'index lues, aucun billet React2Shell trouvé dans les pages accessibles ; non recherchés plus loin.
- Les dépôts de la campagne eux-mêmes : **volontairement non consultés**. Ils contiennent des secrets volés à des tiers ; les lire n'apporte rien à la détection et reviendrait à manipuler des données de victimes.
- Rapports chiffrant wfx-loot (« jusqu'à 4 837 comptes ») : SRC-001 les cite sans les nommer, non retrouvés.
