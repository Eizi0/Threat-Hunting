// ROUTE DE LABORATOIRE UNIQUEMENT. Reproduit, dans le processus Next.js, les comportements de collecte
// décrits pour fast_recon.js (OpenSourceMalware, 18/11/2026), pour mesurer ce que voit la télémétrie hôte.
// Aucune exploitation : la route est appelée normalement. Les secrets lus sont factices, les API d'IA
// sont résolues vers un trou noir DNS local (dnsmasq) et rien ne quitte la machine.
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
export const dynamic = 'force-dynamic';
const AI = ['api.openai.com','api.anthropic.com','generativelanguage.googleapis.com','api.deepseek.com','openrouter.ai'];
export async function GET() {
  // Garde-fou : refuser de tourner si le résolveur système ne pointe pas vers le trou noir dnsmasq local
  // (ajouté après un premier essai lancé sans lui : 5 requêtes réelles, clé factice, toutes rejetées en 401).
  const resolv = fs.readFileSync('/etc/resolv.conf', 'utf8');
  if (!/^nameserver 127\.0\.0\.1\s*$/m.test(resolv) || /^nameserver (?!127\.0\.0\.1)/m.test(resolv)) {
    return Response.json({ refused: 'trou noir DNS inactif' }, { status: 503 });
  }
  const out ={ env_vars_count: Object.keys(process.env).length, hostname: os.hostname(), files: {}, llm_checks: {} };
  const home = os.homedir();
  const candidates = [
    path.join(home, '.aws/credentials'), path.join(home, '.aws/config'),
    '/var/run/secrets/kubernetes.io/serviceaccount/token',
    ...fs.readdirSync(process.cwd()).filter(f => f.startsWith('.env')).map(f => path.join(process.cwd(), f)),
  ];
  for (const f of candidates) { try { out.files[f] = fs.readFileSync(f, 'utf8').length; } catch (e) { out.files[f] = e.code; } }
  try { out.listening = fs.readFileSync('/proc/net/tcp', 'utf8').split('\n').length; } catch {}
  try { out.procs = fs.readdirSync('/proc').filter(d => /^\d+$/.test(d)).length; } catch {}
  for (const w of ['/tmp', '/var/tmp', '/dev/shm', process.cwd()]) { try { fs.accessSync(w, fs.constants.W_OK); (out.writable ??= []).push(w); } catch {} }
  for (const h of AI) {
    try {
      const r = await fetch(`https://${h}/v1/models`, { headers: { 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36', Authorization: 'Bearer FAKE-LAB-KEY' }, signal: AbortSignal.timeout(3000) });
      out.llm_checks[h] = r.status;
    } catch (e) { out.llm_checks[h] = e.cause?.code || e.name; }
  }
  return Response.json(out);
}
