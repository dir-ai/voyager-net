import http from 'node:http'
import https from 'node:https'
import type { LookupFunction } from 'node:net'
import { blockedMetadataReason } from './authorize.js'
import type { NetFinding } from './types.js'

/**
 * HTTP path-exposure probes (Kimi Canto VI #35). GET "/" hygiene misses the classic
 * over-shares that have their own nmap scripts: Apache mod_status (/server-status),
 * mod_info (/server-info), and nginx stub_status. Each leaks live internals (client
 * IPs, request URLs, worker state, module config) to anyone. We fetch a SMALL fixed
 * set of well-known paths, pinned to the vetted IP, and flag only a CONFIRMED body
 * signature — never a guess from a 200. Read-only GET, bounded, no crawling.
 */
interface Exposure {
  path: string
  kind: string
  /** A body signature that CONFIRMS the sensitive page actually rendered. */
  sig: RegExp
  detail: string
  fix: string
}

const EXPOSURES: Exposure[] = [
  { path: '/server-status?auto', kind: 'apache-server-status', sig: /Total Accesses:|BusyWorkers:|Scoreboard:/, detail: 'Apache mod_status (/server-status) is world-readable — leaks live request URLs, client IPs and worker state', fix: 'restrict <Location /server-status> with `Require local` (or remove mod_status)' },
  { path: '/server-info', kind: 'apache-server-info', sig: /Apache Server Information|<h1>Server Settings|Module Name:/i, detail: 'Apache mod_info (/server-info) is world-readable — leaks the full module + directive configuration', fix: 'restrict <Location /server-info> with `Require local` (or remove mod_info)' },
  { path: '/nginx_status', kind: 'nginx-stub-status', sig: /Active connections:\s*\d+[\s\S]*server accepts handled requests/, detail: 'nginx stub_status (/nginx_status) is world-readable — leaks connection/throughput internals', fix: 'restrict the stub_status location with `allow 127.0.0.1; deny all;`' },
]

function pinnedGet(pin: string, host: string, port: number, secure: boolean, path: string, timeoutMs: number): Promise<string | null> {
  const mod = secure ? https : http
  const family = pin.includes(':') ? 6 : 4
  const lookup = ((_h: string, options: { all?: boolean } | number, cb: (...a: unknown[]) => void) => {
    if (blockedMetadataReason(pin)) { cb(new Error(`pinned IP ${pin} blocked`)); return }
    if (typeof options === 'object' && options?.all === true) cb(null, [{ address: pin, family }])
    else cb(null, pin, family)
  }) as unknown as LookupFunction
  return new Promise((resolve) => {
    let settled = false
    const done = (v: string | null) => { if (!settled) { settled = true; clearTimeout(timer); resolve(v) } }
    const req = mod.request(
      { protocol: secure ? 'https:' : 'http:', hostname: host, port, path, method: 'GET', lookup, servername: secure ? host : undefined, headers: { 'User-Agent': 'voyager-net/1 (authorized read-only audit)', Host: `${host}:${port}` }, ...(secure ? { rejectUnauthorized: false } : {}) },
      (res) => {
        if ((res.statusCode ?? 0) !== 200) { res.destroy(); return done(null) }
        const chunks: Buffer[] = []
        let size = 0
        res.on('data', (d: Buffer) => { size += d.length; if (size <= 32 * 1024) chunks.push(d); else res.destroy() })
        const end = () => done(Buffer.concat(chunks).toString('latin1'))
        res.on('end', end); res.on('close', end); res.on('error', () => done(null))
      },
    )
    const timer = setTimeout(() => { req.destroy(); done(null) }, timeoutMs)
    req.on('error', () => done(null))
    req.end()
  })
}

export async function scanHttpExposure(pin: string, host: string, port: number, secure: boolean, timeoutMs = 6000): Promise<NetFinding[]> {
  const out = await Promise.all(EXPOSURES.map(async (e) => {
    const body = await pinnedGet(pin, host, port, secure, e.path, timeoutMs)
    if (body == null || !e.sig.test(body)) return null
    return {
      severity: 'high', kind: e.kind, detail: e.detail, at: `${secure ? 'https' : 'http'}://${host}:${port}${e.path}`,
      suggestedFix: e.fix, confidence: 'strong',
    } as NetFinding
  }))
  return out.filter((f): f is NetFinding => f != null)
}
