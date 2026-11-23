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

## Non lu / non utilisé

- Pages NVD de CVE-2025-29927 et CVE-2025-55182 : HTTP 200 mais contenu rendu côté client, rien d'exploitable. Scores repris des avis éditeurs, pas de NVD.
- Bulletins WAF des hébergeurs (Vercel KB, AWS, Google Cloud, Fastly, Akamai, Netlify) cités par SRC-007 : non lus.
- Les dépôts de la campagne eux-mêmes : **volontairement non consultés**. Ils contiennent des secrets volés à des tiers ; les lire n'apporte rien à la détection et reviendrait à manipuler des données de victimes.
- Rapports chiffrant wfx-loot (« jusqu'à 4 837 comptes ») : SRC-001 les cite sans les nommer, non retrouvés.
