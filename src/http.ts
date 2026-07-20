import http from 'node:http'
import https from 'node:https'
import type { LookupFunction } from 'node:net'
import { stripInjection } from '@dir-ai/voyager'
import { defang } from './fingerprint.js'
import { blockedMetadataReason } from './authorize.js'
import type { HttpSurface } from './types.js'

const SEC_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
]

function cookieFlags(line: string): { name: string; secure: boolean; httpOnly: boolean; sameSite: boolean } {
  const name = /^\s*([^=;\s]+)\s*=/.exec(line)?.[1] ?? '(unnamed)'
  const s = line.toLowerCase()
  return { name: stripInjection(name).slice(0, 60), secure: /;\s*secure/.test(s), httpOnly: /;\s*httponly/.test(s), sameSite: /;\s*samesite=/.test(s) }
}

/** Read-only fetch of the root, PINNED to the pre-vetted IP (defeats DNS
 *  rebinding — undici's global fetch would re-resolve the hostname). Connects to
 *  `pinnedIp` while presenting the real hostname as Host + TLS SNI. Reads status,
 *  Server banner, security headers, per-cookie flags, CORS — GET "/" only, no
 *  crawling, no path probing, no redirect following, bounded and abortable. */
/** Known web apps whose exposure matters, matched by distinctive body/header
 *  signatures. Turns "HTTP with weak headers" into "Jenkins/Grafana/... exposed". */
const APP_SIGNATURES: Array<{ app: string; re: RegExp }> = [
  { app: 'Jenkins', re: /X-Jenkins|jenkins-session|<title>[^<]*Jenkins|Dashboard \[Jenkins\]/i },
  { app: 'Grafana', re: /grafana[-_]?boot|<title>Grafana|grafanaBootData/i },
  { app: 'phpMyAdmin', re: /phpMyAdmin|pma_[a-z]+|<title>[^<]*phpMyAdmin/i },
  { app: 'Kibana', re: /kbn-name|<title>Kibana|kibana-body/i },
  { app: 'SonarQube', re: /<title>SonarQube|sonar\.min\.js|window\.sonar/i },
  { app: 'GitLab', re: /gitlab|GitLab|<meta content="GitLab"/i },
  { app: 'Jupyter', re: /jupyter|<title>Jupyter|_xsrf/i },
  { app: 'Argo CD', re: /argo-?cd|<title>Argo/i },
  { app: 'Portainer', re: /portainer|<title>Portainer/i },
  { app: 'WordPress', re: /wp-content|wp-includes|<meta name="generator" content="WordPress/i },
  { app: 'Traefik', re: /traefik|Traefik/i },
  { app: 'MinIO', re: /minio|<title>MinIO/i },
  { app: 'Harbor', re: /harbor|<title>Harbor/i },
]

/** Extract a web-app identity from a bounded body + X-Powered-By. FRAMED output. */
function fingerprintApp(body: string, xPoweredBy: string | null | undefined): string | null {
  for (const s of APP_SIGNATURES) if (s.re.test(body)) return s.app
  const gen = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']{2,60})["']/i.exec(body)?.[1]
  if (gen) return stripInjection(gen).slice(0, 60)
  const title = /<title[^>]*>([^<]{2,80})<\/title>/i.exec(body)?.[1]?.trim()
  if (title) return stripInjection(title).slice(0, 60)
  if (xPoweredBy && xPoweredBy.trim()) return stripInjection(xPoweredBy).slice(0, 60)
  return null
}

export async function inspectHttp(pinnedIp: string, hostname: string, port: number, secure: boolean, timeoutMs = 6000): Promise<HttpSurface | null> {
  const mod = secure ? https : http
  const url = `${secure ? 'https' : 'http'}://${hostname}:${port}/`
  const family = pinnedIp.includes(':') ? 6 : 4
  const lookup = ((_h: string, options: { all?: boolean } | number, cb: (...a: unknown[]) => void) => {
    if (blockedMetadataReason(pinnedIp)) { cb(new Error(`pinned IP ${pinnedIp} blocked`)); return }
    if (typeof options === 'object' && options?.all === true) cb(null, [{ address: pinnedIp, family }])
    else cb(null, pinnedIp, family)
  }) as unknown as LookupFunction

  return new Promise<HttpSurface | null>((resolve) => {
    let settled = false
    const done = (v: HttpSurface | null) => { if (!settled) { settled = true; clearTimeout(timer); resolve(v) } }
    const req = mod.request(
      { protocol: secure ? 'https:' : 'http:', hostname, port, path: '/', method: 'GET', lookup, servername: secure ? hostname : undefined, headers: { 'User-Agent': 'voyager-net/1 (authorized read-only audit)', Host: `${hostname}:${port}` }, ...(secure ? { rejectUnauthorized: false } : {}) },
      (res) => {
        const present: Record<string, boolean> = {}
        for (const hName of SEC_HEADERS) present[hName] = res.headers[hName] !== undefined
        const first = (v: string | string[] | undefined): string | null => (Array.isArray(v) ? v[0] : v ?? null)
        const server = first(res.headers['server'])
        const location = first(res.headers['location'])
        const acao = first(res.headers['access-control-allow-origin'])
        const xpb = first(res.headers['x-powered-by'])
        // Read a BOUNDED chunk of the body to fingerprint the web app (title /
        // generator / known signatures) — "Jenkins exposed", not just "weak headers".
        const ct = (first(res.headers['content-type']) ?? '').toLowerCase()
        const wantsBody = /text\/html|application\/json|text\/plain/.test(ct) || ct === ''
        const chunks: Buffer[] = []
        let size = 0
        const finishWith = (): void => {
          const body = Buffer.concat(chunks).toString('latin1')
          done({
            port, url, status: res.statusCode ?? null,
            server: server ? defang(stripInjection(server)).slice(0, 120) : null,
            securityHeaders: present,
            headerValues: {
              hsts: first(res.headers['strict-transport-security']),
              csp: (() => { const c = first(res.headers['content-security-policy']); return c ? stripInjection(c).slice(0, 400) : null })(),
            },
            cookies: (res.headers['set-cookie'] ?? []).slice(0, 30).map(cookieFlags),
            cors: acao ? stripInjection(acao).slice(0, 120) : null,
            corsCredentials: (first(res.headers['access-control-allow-credentials']) ?? '').toLowerCase() === 'true',
            redirectsToHttps: !secure && (res.statusCode ?? 0) >= 300 && (res.statusCode ?? 0) < 400 && /^https:\/\//i.test(location ?? ''),
            app: fingerprintApp(body, xpb),
          })
        }
        if (!wantsBody) { res.destroy(); finishWith(); return }
        res.on('data', (d: Buffer) => { size += d.length; if (size <= 32 * 1024) chunks.push(d); if (size > 32 * 1024) res.destroy() })
        res.on('end', finishWith)
        res.on('close', finishWith)
        res.on('error', () => done(null))
      },
    )
    const timer = setTimeout(() => { req.destroy(); done(null) }, timeoutMs)
    req.on('error', () => done(null))
    req.end()
  })
}
