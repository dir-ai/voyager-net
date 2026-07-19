import http from 'node:http'
import https from 'node:https'
import type { LookupFunction } from 'node:net'
import { stripInjection } from '@dir-ai/voyager'
import { defang } from './fingerprint.js'
import { blockedIpReason } from './authorize.js'
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
export async function inspectHttp(pinnedIp: string, hostname: string, port: number, secure: boolean, timeoutMs = 6000): Promise<HttpSurface | null> {
  const mod = secure ? https : http
  const url = `${secure ? 'https' : 'http'}://${hostname}:${port}/`
  const family = pinnedIp.includes(':') ? 6 : 4
  const lookup = ((_h: string, options: { all?: boolean } | number, cb: (...a: unknown[]) => void) => {
    if (blockedIpReason(pinnedIp)) { cb(new Error(`pinned IP ${pinnedIp} blocked`)); return }
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
        res.destroy() // headers are enough; do not read the body
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
        })
      },
    )
    const timer = setTimeout(() => { req.destroy(); done(null) }, timeoutMs)
    req.on('error', () => done(null))
    req.end()
  })
}
