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

/** Read-only fetch of the root: status, Server banner (framed), security headers.
 *  A GET of "/" only — no crawling, no probing paths, bounded and abortable. */
export async function inspectHttp(host: string, port: number, secure: boolean, timeoutMs = 6000): Promise<HttpSurface | null> {
  const url = `${secure ? 'https' : 'http'}://${host}:${port}/`
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'manual', signal: ctrl.signal, headers: { 'User-Agent': 'voyager-net/1 (authorized read-only audit)' } })
    const present: Record<string, boolean> = {}
    for (const h of SEC_HEADERS) present[h] = res.headers.has(h)
    const server = res.headers.get('server')
    return {
      port,
      url,
      status: res.status,
      server: server ? stripInjection(server).slice(0, 120) : null,
      securityHeaders: present,
    }
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}
