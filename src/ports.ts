import net from 'node:net'
import type { PortResult } from './types.js'

// A small, common service set — enough to spot an exposed surface without
// behaving like a scanner. NOT a full 65k sweep (that would be intrusive).
export const DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 3000, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]

const SERVICE: Record<number, string> = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
  443: 'https', 445: 'smb', 587: 'smtp-submission', 993: 'imaps', 995: 'pop3s', 3000: 'http-dev',
  3306: 'mysql', 3389: 'rdp', 5432: 'postgres', 5900: 'vnc', 6379: 'redis', 8080: 'http-alt',
  8443: 'https-alt', 9200: 'elasticsearch', 27017: 'mongodb',
}

/** A single TCP connect() probe — the read-only, non-intrusive way to tell if a
 *  port accepts connections. No raw sockets, no SYN tricks, no payloads. */
function probe(host: string, port: number, timeoutMs: number): Promise<PortResult> {
  return new Promise((resolve) => {
    const sock = new net.Socket()
    let settled = false
    const done = (open: boolean) => {
      if (settled) return
      settled = true
      sock.destroy()
      resolve({ port, open, service: open ? SERVICE[port] : undefined })
    }
    sock.setTimeout(timeoutMs)
    sock.once('connect', () => done(true))
    sock.once('timeout', () => done(false))
    sock.once('error', () => done(false))
    try {
      sock.connect(port, host)
    } catch {
      done(false)
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
