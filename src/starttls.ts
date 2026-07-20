import net from 'node:net'
import tls from 'node:tls'
import type { NetFinding } from './types.js'

/**
 * STARTTLS weak-TLS detection (Kimi #5). A mail service on :25/:587/:143/:110 speaks
 * plaintext first, then upgrades to TLS via a STARTTLS command — so the direct-TLS
 * probe never sees it, and a server that upgrades to TLSv1/1.1 looks clean. We do the
 * protocol-specific dance (EHLO+STARTTLS for SMTP, `a STARTTLS` for IMAP, `STLS` for
 * POP3), then attempt a TLSv1/1.1 handshake over the upgraded socket. Read-only: no
 * auth, no mail sent — just the negotiation. Pinned to the vetted IP.
 */
interface Dance { greetOk: RegExp; cmd: string; go: RegExp }
const SMTP: Dance = { greetOk: /^220/m, cmd: 'EHLO voyager.local\r\nSTARTTLS\r\n', go: /^220/m }
const IMAP: Dance = { greetOk: /^\*\s*OK/im, cmd: 'a1 STARTTLS\r\n', go: /a1 OK/i }
const POP3: Dance = { greetOk: /^\+OK/m, cmd: 'STLS\r\n', go: /^\+OK/m }
const DANCE_BY_PORT: Record<number, Dance> = { 25: SMTP, 587: SMTP, 465: SMTP, 143: IMAP, 110: POP3 }

/** Pick the STARTTLS dance by well-known port OR by the fingerprinted product — so a
 *  Postfix on :2525 (Kimi R3-6: fingerprint sees it, the dance was port-keyed) upgrades
 *  correctly. Returns null when the port/service isn't a STARTTLS mail protocol. */
function pickDance(port: number, hint: string): Dance | null {
  if (DANCE_BY_PORT[port]) return DANCE_BY_PORT[port]
  const h = hint.toLowerCase()
  if (/smtp|postfix|exim|sendmail|mail/.test(h)) return SMTP
  if (/imap|dovecot|cyrus/.test(h)) return IMAP
  if (/pop3|pop\b/.test(h)) return POP3
  return null
}

export async function inspectStartTls(pin: string, host: string, port: number, timeoutMs: number, hint = ''): Promise<NetFinding[]> {
  const d = pickDance(port, hint)
  if (!d) return []
  const weak = await probeWeak(pin, port, d, timeoutMs)
  if (!weak.length) return []
  return [{
    severity: 'high', kind: 'weak-tls', detail: `STARTTLS on port ${port} negotiates deprecated ${weak.join(' + ')} (invisible to a direct-TLS probe)`,
    at: `${host}:${port}`, suggestedFix: 'require TLS 1.2+ on the STARTTLS upgrade; disable TLS 1.0/1.1', confidence: 'strong',
  }]
}

/** Try a TLSv1 and a TLSv1.1 handshake AFTER the STARTTLS upgrade; return those that succeed. */
async function probeWeak(pin: string, port: number, d: Dance, timeoutMs: number): Promise<string[]> {
  const out: string[] = []
  for (const version of ['TLSv1', 'TLSv1.1'] as const) {
    if (await handshakes(pin, port, d, version, timeoutMs)) out.push(version)
  }
  return out
}

function handshakes(pin: string, port: number, d: Dance, version: 'TLSv1' | 'TLSv1.1', timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = new net.Socket()
    let stage: 'greet' | 'go' = 'greet'
    let buf = ''
    let done = false
    const finish = (v: boolean): void => { if (done) return; done = true; try { sock.destroy() } catch { /* */ } resolve(v) }
    sock.setTimeout(timeoutMs)
    sock.once('timeout', () => finish(false))
    sock.once('error', () => finish(false))
    sock.on('data', (chunk) => {
      buf += chunk.toString('latin1')
      if (stage === 'greet' && d.greetOk.test(buf)) { stage = 'go'; buf = ''; sock.write(d.cmd); return }
      if (stage === 'go' && d.go.test(buf)) {
        // The server agreed to upgrade — attempt the weak TLS handshake over this socket.
        const secure = tls.connect({ socket: sock, minVersion: version, maxVersion: version, rejectUnauthorized: false, ciphers: 'DEFAULT@SECLEVEL=0' } as tls.ConnectionOptions)
        secure.once('secureConnect', () => finish(true))
        secure.once('error', () => finish(false))
        stage = 'greet' // prevent re-entry
      }
    })
    try { sock.connect(port, pin) } catch { finish(false) }
  })
}
