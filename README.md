# Threat Hunting

Dossiers d'investigation sur des menaces d'actualité : sources recoupées, affirmations tracées, preuves de laboratoire, règles de détection et outils de vérification. Un dossier par cas, rattaché à un article du blog [jeovany.com](https://www.jeovany.com/blog/).

Approche strictement défensive : toute simulation en laboratoire sert à produire de la télémétrie à détecter, jamais à attaquer. Aucun échantillon malveillant n'est publié ici.

## Cas

| Cas | Sujet | Article |
|---|---|---|
| [2026-10-cursor-claude-code-2.1.313](cases/2026-10-cursor-claude-code-2.1.313/) | Extension Claude Code piégée servie par la marketplace de Cursor : porte dérobée SSH | [Lire l'article](https://www.jeovany.com/blog/claude-code-cursor-porte-derobee-ssh/) |

## Structure d'un cas

```
cases/<AAAA-MM-sujet>/
  README.md          résumé, contenu, limites
  sources.md         sources lues et fiabilité, ce qui n'a pas pu être lu
  claims.md          affirmations, statut de preuve, formulation autorisée
  experiment-log.md  expériences : environnement, méthode, résultats, limites
  evidence/          IOCs et preuves brutes (anonymisées)
  detection/         règles Sigma et outils de vérification
```

Niveaux de preuve utilisés dans `claims.md` : **A** incident rapporté · **B** analyse statique d'un tiers · **C** vérifié en laboratoire · **D** déduit.

Chaque règle de détection indique ce qui a été testé et ce qui ne l'a pas été.
