import net from 'node:net'
import { defang } from './fingerprint.js'
import type { NetFinding, PortResult } from './types.js'

/**
 * Unauthenticated-service detection (N1). An OPEN datastore/admin port is not the
 * finding — an open port that answers a benign protocol probe WITHOUT asking for
 * credentials is. For each known auth-expecting service we send ONE harmless,
 * read-only command and classify the reply:
 *   - `exposed`      → it returned data with no auth  → CRITICAL.
 *   - `authRequired` → it demanded auth (e.g. Redis NOAUTH) → good, reported clean.
 *   - neither        → inconclusive → left UNKNOWN, never called clean.
 * No write, no mutation, no exploit — a single protocol hello, and only against a
 * host the caller authorized. This is the "exposed vs merely open" distinction a
 * real audit needs (Kimi N1: an open Redis with no password).
 */
interface UnauthProbe {
  service: string
  /** Bytes to send after connect; null = read the banner the service volunteers. */
  send: string | null
  /** Reply proves the service answered WITHOUT authentication. */
  exposed: (resp: string) => boolean
  /** Reply proves the service demanded authentication (the safe outcome). */
  authRequired: (resp: string) => boolean
}

const PROBES: Record<number, UnauthProbe> = {
  6379: { service: 'Redis', send: 'PING\r\n', exposed: (r) => /\+PONG/.test(r), authRequired: (r) => /NOAUTH|WRONGPASS|-ERR[^\n]*auth/i.test(r) },
  11211: { service: 'Memcached', send: 'version\r\n', exposed: (r) => /^VERSION\s/i.test(r.trim()), authRequired: () => false },
  9200: { service: 'Elasticsearch', send: 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n', exposed: (r) => /"cluster_name"|"lucene_version"|"number_of_nodes"/.test(r), authRequired: (r) => /\b401\b|security_exception|missing authentication/i.test(r) },
  5984: { service: 'CouchDB', send: 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n', exposed: (r) => /"couchdb"\s*:\s*"Welcome"/.test(r), authRequired: (r) => /\b401\b|unauthorized/i.test(r) },
  2375: { service: 'Docker Engine API', send: 'GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n', exposed: (r) => /"ApiVersion"|"DockerRootDir"|"GoVersion"/.test(r), authRequired: (r) => /\b401\b/.test(r) },
  2181: { service: 'ZooKeeper', send: 'ruok', exposed: (r) => /imok/.test(r), authRequired: () => false },
}

/** Ports worth adding to the default sweep because they host unauth-prone services. */
export const UNAUTH_PORTS = Object.keys(PROBES).map(Number)

/** Probe every open port that maps to a known auth-expecting service. Returns a
 *  finding per exposed service (and a clean note is left to the caller). */
export async function scanUnauth(pin: string, host: string, open: PortResult[], timeoutMs: number): Promise<NetFinding[]> {
  const targets = open.filter((p) => PROBES[p.port])
  const out = await Promise.all(
    targets.map(async (p) => {
      const probe = PROBES[p.port]
      const resp = await talk(pin, p.port, probe.send, timeoutMs)
      if (resp == null) return null
      if (probe.exposed(resp)) {
        return {
          severity: 'critical',
          kind: 'unauthenticated-service',
          detail: `${probe.service} answered a protocol probe WITHOUT authentication — the datastore/API is exposed (framed reply: ${defang(resp.replace(/\s+/g, ' ').slice(0, 80))})`,
          at: `${host}:${p.port}`,
          suggestedFix: `require authentication on ${probe.service} and firewall the port to trusted networks only — an unauthenticated ${probe.service} is remote data access/RCE-adjacent`,
          confidence: 'strong',
        } as NetFinding
      }
      if (probe.authRequired(resp)) {
        return {
          severity: 'info', kind: 'service-auth-ok', detail: `${probe.service} required authentication (probe rejected) — good`,
          at: `${host}:${p.port}`, suggestedFix: 'no action — the service is not anonymously exposed', confidence: 'moderate',
        } as NetFinding
      }
      return null // inconclusive → stays UNKNOWN
    }),
  )
  return out.filter(Boolean) as NetFinding[]
}

/** One benign request/response over raw TCP, pinned to the vetted IP. Reads until
 *  the peer pauses or the deadline, whichever first; never writes twice. */
function talk(ip: string, port: number, send: string | null, timeoutMs: number): Promise<string | null> {
  return new Promise((resolve) => {
    const sock = new net.Socket()
    let buf = ''
    let done = false
    const finish = (v: string | null): void => {
      if (done) return
      done = true
      try { sock.destroy() } catch { /* noop */ }
      resolve(v)
    }
    sock.setTimeout(timeoutMs)
    sock.once('timeout', () => finish(buf || null))
    sock.once('error', () => finish(buf || null))
    sock.once('connect', () => {
      if (send) sock.write(send)
    })
    sock.on('data', (d) => {
      buf += d.toString('latin1')
      if (buf.length > 4096) finish(buf) // enough to classify; don't drain a firehose
    })
    sock.once('close', () => finish(buf || null))
    try {
      sock.connect(port, ip)
    } catch {
      finish(null)
    }
  })
}
