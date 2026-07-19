import { stripInjection } from '@dir-ai/voyager'
import type { HttpSurface } from './types.js'

const SEC_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
]

function parseCookieFlags(setCookie: string | null): HttpSurface['cookies'] {
  if (!setCookie) return null
  const s = setCookie.toLowerCase()
  return { secure: /;\s*secure/.test(s), httpOnly: /;\s*httponly/.test(s), sameSite: /;\s*samesite=/.test(s) }
}

/** Read-only fetch of the root: status, Server banner (framed), security headers,
 *  cookie flags, CORS, and whether an http:// root upgrades to https. GET "/" only
 *  — no crawling, no path probing, bounded and abortable. */
export async function inspectHttp(host: string, port: number, secure: boolean, timeoutMs = 6000): Promise<HttpSurface | null> {
  const url = `${secure ? 'https' : 'http'}://${host}:${port}/`
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'manual', signal: ctrl.signal, headers: { 'User-Agent': 'voyager-net/1 (authorized read-only audit)' } })
    const present: Record<string, boolean> = {}
    for (const h of SEC_HEADERS) present[h] = res.headers.has(h)
    const server = res.headers.get('server')
    const location = res.headers.get('location')
    const redirectsToHttps = !secure && res.status >= 300 && res.status < 400 && /^https:\/\//i.test(location ?? '')
    return {
      port, url, status: res.status,
      server: server ? stripInjection(server).slice(0, 120) : null,
      securityHeaders: present,
      cookies: parseCookieFlags(res.headers.get('set-cookie')),
      cors: res.headers.get('access-control-allow-origin'),
      redirectsToHttps,
    }
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}
