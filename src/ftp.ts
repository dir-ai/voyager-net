import net from 'node:net'
import { defang } from './fingerprint.js'
import type { NetFinding } from './types.js'

/**
 * FTP anonymous-login check (Kimi Canto VI #34). nmap has a dedicated `ftp-anon`
 * script; we were only reading the version banner. A real anonymous login — USER
 * anonymous / PASS anonymous@ → 230 — means the world can list/read (often write)
 * the server's files. Read-only: we authenticate anonymously, then immediately QUIT;
 * we never LIST, RETR, or STOR. Pinned to the vetted IP.
 */
export function scanFtp(pin: string, host: string, port: number, timeoutMs: number): Promise<NetFinding[]> {
  return new Promise((resolve) => {
    const sock = new net.Socket()
    let buf = ''
    let stage: 'banner' | 'user' | 'pass' | 'done' = 'banner'
    let done = false
    const finish = (findings: NetFinding[]): void => {
      if (done) return
      done = true
      try { sock.write('QUIT\r\n') } catch { /* noop */ }
      try { sock.destroy() } catch { /* noop */ }
      resolve(findings)
    }
    // The most recent COMPLETE reply line's 3-digit code ("230 Login successful").
    const lastCode = (): string | null => {
      const lines = buf.split(/\r?\n/).filter((l) => /^\d{3}[ -]/.test(l))
      return lines.length ? lines[lines.length - 1].slice(0, 3) : null
    }
    const exposed = (): NetFinding => ({
      severity: 'high', kind: 'ftp-anonymous',
      detail: `FTP allows ANONYMOUS login (USER anonymous → 230) — files are readable without credentials${buf.includes('230') ? ` (${defang(/230[ -]([^\r\n]{0,60})/.exec(buf)?.[1]?.trim() ?? 'login successful')})` : ''}`,
      at: `${host}:${port}`,
      suggestedFix: 'disable anonymous FTP (or restrict it read-only to a jailed public dir); prefer SFTP/FTPS with real accounts',
      confidence: 'strong',
    })
    sock.setTimeout(timeoutMs)
    sock.once('timeout', () => finish([]))
    sock.once('error', () => finish([]))
    sock.once('close', () => finish([]))
    sock.on('data', (d) => {
      buf += d.toString('latin1')
      if (buf.length > 8192) return finish([])
      const code = lastCode()
      if (stage === 'banner' && code === '220') { stage = 'user'; sock.write('USER anonymous\r\n') }
      else if (stage === 'user' && code === '331') { stage = 'pass'; buf = ''; sock.write('PASS anonymous@example.com\r\n') }
      else if (stage === 'user' && code === '230') { stage = 'done'; finish([exposed()]) }      // some servers skip PASS
      else if (stage === 'pass' && code === '230') { stage = 'done'; finish([exposed()]) }
      else if ((stage === 'user' || stage === 'pass') && (code === '530' || code === '421')) finish([]) // rejected — good
    })
    try { sock.connect(port, pin) } catch { finish([]) }
  })
}
