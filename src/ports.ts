import net from 'node:net'
import { fingerprintBanner } from './fingerprint.js'
import type { PortResult, PortState } from './types.js'

// A small, common service set — enough to spot an exposed surface without
// behaving like a scanner. NOT a full 65k sweep (that would be intrusive).
export const DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 3000, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]

const SERVICE: Record<number, string> = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
  443: 'https', 445: 'smb', 587: 'smtp-submission', 993: 'imaps', 995: 'pop3s', 3000: 'http-dev',
  3306: 'mysql', 3389: 'rdp', 5432: 'postgres', 5900: 'vnc', 6379: 'redis', 8080: 'http-alt',
  8443: 'https-alt', 9200: 'elasticsearch', 27017: 'mongodb',
}

// Ports that only speak after WE send bytes (HTTP) or are binary/TLS — don't wait
// for a volunteered banner there; dedicated inspectors (tls/http) handle them.
const NO_PASSIVE_BANNER = new Set([80, 443, 8080, 8443, 3000, 6379, 3306, 5432, 27017, 9200])

/**
 * A single TCP connect() probe — the read-only way to tell if a port accepts
 * connections. Distinguishes the REAL state (Codex #1): open / closed (refused) /
 * filtered (dropped → timeout) / unreachable (no route). On open, PASSIVELY reads
 * a volunteered banner (we send nothing) for a short window, then closes.
 */
function probe(host: string, port: number, timeoutMs: number): Promise<PortResult> {
  return new Promise((resolve) => {
    const sock = new net.Socket()
    let settled = false
    let banner = ''
    const finish = (state: PortState) => {
      if (settled) return
      settled = true
      const service = SERVICE[port]
      const fp = state === 'open' && banner ? fingerprintBanner(banner, port) : undefined
      sock.destroy()
      resolve({ port, state, open: state === 'open', service, banner: fp?.banner, product: fp?.product, version: fp?.version })
    }
    sock.setTimeout(timeoutMs)
    sock.once('timeout', () => finish('filtered')) // dropped packets → filtered
    sock.once('error', (e: NodeJS.ErrnoException) => {
      // ECONNREFUSED = actively closed; host/net-unreach = no route; a timeout/reset
      // at the OS level (ETIMEDOUT) means the packet was dropped → filtered, NOT closed.
      finish(
        e.code === 'ECONNREFUSED'
          ? 'closed'
          : e.code === 'EHOSTUNREACH' || e.code === 'ENETUNREACH'
            ? 'unreachable'
            : e.code === 'ETIMEDOUT'
              ? 'filtered'
              : 'closed',
      )
    })
    sock.once('connect', () => {
      if (NO_PASSIVE_BANNER.has(port)) return finish('open')
      // Passive: send NOTHING; give the server a brief moment to volunteer a banner.
      const bannerTimer = setTimeout(() => finish('open'), Math.min(1500, timeoutMs))
      sock.on('data', (d: Buffer) => {
        banner += d.toString('latin1')
        if (banner.length >= 512) { clearTimeout(bannerTimer); finish('open') }
      })
      sock.once('end', () => { clearTimeout(bannerTimer); finish('open') })
    })
    try {
      sock.connect(port, host)
    } catch {
      finish('closed')
    }
  })
}

/** Probe a bounded port set with limited concurrency (never floods the target). */
export async function scanPorts(host: string, ports: number[], timeoutMs = 3000, concurrency = 8): Promise<PortResult[]> {
  const results: PortResult[] = []
  const queue = [...ports]
  const workers = Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
    for (;;) {
      const p = queue.shift()
      if (p === undefined) break
      results.push(await probe(host, p, timeoutMs))
    }
  })
  await Promise.all(workers)
  return results.sort((a, b) => a.port - b.port)
}
