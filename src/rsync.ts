import net from 'node:net'
import { defang } from './fingerprint.js'
import type { NetFinding } from './types.js'

/**
 * rsync daemon module enumeration (Kimi Canto VI — beyond the banner). The unauth
 * probe already flags an rsync daemon from its `@RSYNCD:` greeting; this goes one
 * step further and completes the version handshake, then requests the MODULE LIST.
 * Each listed module is an anonymously-reachable share (often world-readable, the
 * classic rsync data-leak). Read-only: we echo the version and ask for the listing,
 * then close — we never enter a module or transfer a file. Pinned to the vetted IP.
 *
 * Protocol: server → "@RSYNCD: <ver>\n"; client echoes the version line; client sends
 * a blank line to request the module listing; server returns module lines then
 * "@RSYNCD: EXIT".
 */
export function scanRsyncModules(pin: string, host: string, port: number, timeoutMs: number): Promise<NetFinding[]> {
  return new Promise((resolve) => {
    const sock = new net.Socket()
    let buf = ''
    let greeted = false
    let done = false
    const finish = (findings: NetFinding[]): void => {
      if (done) return
      done = true
      try { sock.destroy() } catch { /* noop */ }
      resolve(findings)
    }
    const evaluate = (): void => {
      // Module lines are everything that is NOT an @RSYNCD control line and not blank.
      const modules = buf.split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l && !/^@RSYNCD:/.test(l) && !/^@ERROR/.test(l))
        .map((l) => l.split(/\s{2,}|\t/)[0])
        .filter(Boolean)
        .slice(0, 20)
      if (modules.length) {
        finish([{
          severity: 'high', kind: 'rsync-anonymous-module',
          detail: `rsync daemon lists ${modules.length} module(s) WITHOUT authentication: ${defang(modules.join(', ')).slice(0, 120)} — each is an anonymously-reachable share`,
          at: `${host}:${port}`,
          suggestedFix: 'require "auth users" + a secrets file on every rsync module, set "list = no", and firewall port 873 to trusted networks',
          confidence: 'strong',
        }])
      } else finish([])
    }
    sock.setTimeout(timeoutMs)
    sock.once('timeout', () => (greeted ? evaluate() : finish([])))
    sock.once('error', () => finish([]))
    sock.once('close', () => (greeted ? evaluate() : finish([])))
    sock.on('data', (d) => {
      buf += d.toString('latin1')
      if (buf.length > 8192) return evaluate()
      if (!greeted) {
        const m = /@RSYNCD:\s*([0-9.]+)/.exec(buf)
        if (m) {
          greeted = true
          buf = '' // reset so the buffer now collects the module listing only
          sock.write(`@RSYNCD: ${m[1]}\n`) // echo the server's protocol version
          sock.write('\n')                 // blank module name = request the listing
        }
      } else if (/@RSYNCD:\s*EXIT/.test(buf)) evaluate()
    })
    try { sock.connect(port, pin) } catch { finish([]) }
  })
}
