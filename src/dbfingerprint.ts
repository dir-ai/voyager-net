import net from 'node:net'
import { defang } from './fingerprint.js'
import type { NetFinding, PortResult } from './types.js'

/**
 * Database protocol fingerprinting (Kimi round-3 #2). MySQL/MariaDB volunteer a
 * greeting on connect (protocol byte 10 + a cleartext version string — the easiest
 * banner in the world to parse); PostgreSQL doesn't greet but answers an SSLRequest
 * with a single 'S'/'N'; MSSQL answers a TDS pre-login. All READ-ONLY: we read the
 * greeting or send ONE well-formed handshake byte-sequence, never an auth attempt.
 * Runs on any open port not already claimed by TLS/HTTP, so a MySQL on :3316 is
 * identified the same as on :3306. Emits product/version findings the CVE feed can use.
 */
export async function fingerprintDb(pin: string, host: string, open: PortResult[], inspected: Set<number>, timeoutMs: number): Promise<NetFinding[]> {
  const targets = open.filter((p) => !inspected.has(p.port))
  const out = await Promise.all(targets.map((p) => probeDb(pin, host, p.port, timeoutMs)))
  return out.filter(Boolean) as NetFinding[]
}

async function probeDb(pin: string, host: string, port: number, timeoutMs: number): Promise<NetFinding | null> {
  const at = `${host}:${port}`
  // 1) MySQL/MariaDB: server speaks first. Read the greeting.
  const greeting = await rawExchange(pin, port, null, timeoutMs)
  if (greeting && greeting.length > 5 && greeting.charCodeAt(4) === 0x0a) {
    const end = greeting.indexOf('\0', 5)
    const version = defang(greeting.slice(5, end > 5 ? end : 5 + 24).replace(/[^\x20-\x7e]/g, ''))
    const product = /mariadb/i.test(version) ? 'MariaDB' : 'MySQL'
    return {
      severity: 'high', kind: 'exposed-service',
      detail: `${product} ${version} reachable on port ${port} — a database endpoint is exposed (version disclosed in the handshake)`,
      at, suggestedFix: `restrict ${product} to a private network/VPN; check ${product} ${version} against your CVE feed (OSV/NVD)`, confidence: 'strong',
    }
  }
  // 2) PostgreSQL: send SSLRequest (len=8, code=80877103) → replies 'S' or 'N'.
  const ssl = Buffer.from([0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f])
  const pg = await rawExchange(pin, port, ssl, timeoutMs)
  if (pg && pg.length === 1 && (pg[0] === 'S' || pg[0] === 'N')) {
    return { severity: 'high', kind: 'exposed-service', detail: `PostgreSQL reachable on port ${port} (answered SSLRequest with '${pg}') — a database endpoint is exposed`, at, suggestedFix: 'restrict PostgreSQL to a private network/VPN; require TLS + strong auth (pg_hba.conf)', confidence: 'strong' }
  }
  // 3) MSSQL: a minimal TDS pre-login packet → a TDS response (type 0x04).
  const preLogin = Buffer.from([0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20, 0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03, 0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
  const ms = await rawExchange(pin, port, preLogin, timeoutMs)
  if (ms && ms.length > 0 && ms.charCodeAt(0) === 0x04) {
    return { severity: 'high', kind: 'exposed-service', detail: `Microsoft SQL Server reachable on port ${port} (answered a TDS pre-login) — a database endpoint is exposed`, at, suggestedFix: 'restrict MSSQL to a private network/VPN; enforce encryption + strong auth', confidence: 'moderate' }
  }
  return null
}

/** One raw request/response over TCP, pinned to the vetted IP. `send` null = just
 *  read what the server volunteers (for greeting protocols like MySQL). */
function rawExchange(ip: string, port: number, send: Buffer | null, timeoutMs: number): Promise<string | null> {
  return new Promise((resolve) => {
    const sock = new net.Socket()
    let buf = ''
    let done = false
    const finish = (v: string | null): void => { if (done) return; done = true; try { sock.destroy() } catch { /* */ } resolve(v) }
    sock.setTimeout(Math.min(timeoutMs, 4000))
    sock.once('timeout', () => finish(buf || null))
    sock.once('error', () => finish(buf || null))
    sock.once('connect', () => { if (send) sock.write(send) })
    sock.on('data', (d) => { buf += d.toString('latin1'); if (buf.length > 2048) finish(buf) })
    sock.once('close', () => finish(buf || null))
    try { sock.connect(port, ip) } catch { finish(null) }
  })
}
