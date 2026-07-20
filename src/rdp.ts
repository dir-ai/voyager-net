import net from 'node:net'
import { defang } from './fingerprint.js'
import type { NetFinding } from './types.js'

/**
 * RDP NLA + Telnet checks (Kimi P0 #8, remote-access protocols).
 *
 * RDP (:3389): we send an X.224 Connection Request with an RDP Negotiation Request
 * and read the server's chosen protocol. selectedProtocol 0 = standard RDP security
 * with NO Network Level Authentication — the pre-auth attack surface (BlueKeep-class).
 * TLS(1)/CredSSP(2) mean NLA is enforced (good). Read-only: just the negotiation.
 *
 * Telnet (:23): plaintext by construction — any exposed Telnet transmits credentials
 * in the clear. We grab the banner (framed) and flag the cleartext exposure.
 */
export async function inspectRdp(pin: string, host: string, port: number, timeoutMs: number): Promise<NetFinding[]> {
  const proto = await rdpNegotiate(pin, port, timeoutMs)
  if (proto == null) return []
  if (proto === 0) {
    return [{
      severity: 'high', kind: 'rdp-no-nla',
      detail: `RDP on port ${port} accepts Standard RDP Security — Network Level Authentication (NLA) is NOT enforced, exposing the pre-auth surface (BlueKeep-class)`,
      at: `${host}:${port}`, suggestedFix: 'require NLA (CredSSP) on RDP; restrict RDP to a VPN/jump host and patch to a current build', confidence: 'strong',
    }]
  }
  return []
}

export async function inspectTelnet(pin: string, host: string, port: number, timeoutMs: number): Promise<NetFinding[]> {
  const banner = await grab(pin, port, timeoutMs)
  if (banner == null) return []
  // Only flag if it actually looks like Telnet — the IAC negotiation bytes (0xff +
  // 0xfb..0xfe) OR a login/password prompt — so this runs safely on ANY port (Kimi #3)
  // without mislabelling arbitrary banner services.
  const looksTelnet = /\xff[\xfb-\xfe]/.test(banner) || /(?:^|\W)(?:login|username|password)\s*:/i.test(banner)
  if (port !== 23 && !looksTelnet) return []
  const clean = defang(banner.replace(/[^\x20-\x7e]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 80))
  return [{
    severity: 'high', kind: 'telnet-cleartext',
    detail: `Telnet reachable on port ${port} — a PLAINTEXT protocol: credentials and session travel unencrypted${clean ? ` (banner: ${clean})` : ''}`,
    at: `${host}:${port}`, suggestedFix: 'disable Telnet entirely; use SSH instead and firewall port 23', confidence: 'strong',
  }]
}

/** Send an X.224 RDP Negotiation Request; return the server's selectedProtocol (0/1/2) or null. */
function rdpNegotiate(ip: string, port: number, timeoutMs: number): Promise<number | null> {
  return new Promise((resolve) => {
    const sock = new net.Socket()
    let buf = Buffer.alloc(0)
    let done = false
    const finish = (v: number | null): void => { if (done) return; done = true; try { sock.destroy() } catch { /* */ } resolve(v) }
    sock.setTimeout(timeoutMs)
    sock.once('timeout', () => finish(null))
    sock.once('error', () => finish(null))
    sock.once('connect', () => sock.write(rdpCR()))
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d])
      if (buf.length < 19) return // TPKT(4)+X224(7)+RDP_NEG_RSP(8)
      // Find the RDP negotiation response (type 0x02) inside the X.224 payload.
      const idx = buf.indexOf(0x02, 11)
      if (idx >= 0 && idx + 8 <= buf.length && buf[idx + 1] <= 0x0f) finish(buf.readUInt32LE(idx + 4))
      else finish(1) // an X.224 confirm without a neg-response usually means TLS/NLA path
    })
    try { sock.connect(port, ip) } catch { finish(null) }
  })
}

/** The classic X.224 Connection Request + RDP Negotiation Request (request TLS+CredSSP). */
function rdpCR(): Buffer {
  const neg = Buffer.from([0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00]) // TYPE_RDP_NEG_REQ, flags, len=8, requestedProtocols=TLS|CredSSP
  const x224 = Buffer.concat([Buffer.from([0x0e - 1 + neg.length, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00]), neg]) // LI, CR CDT, dst-ref, src-ref, class
  const tpkt = Buffer.from([0x03, 0x00, 0x00, 4 + x224.length])
  return Buffer.concat([tpkt, x224])
}

/** Read whatever a server volunteers on connect (Telnet greets/negotiates first). */
function grab(ip: string, port: number, timeoutMs: number): Promise<string | null> {
  return new Promise((resolve) => {
    const sock = new net.Socket()
    let buf = ''
    let done = false
    const finish = (v: string | null): void => { if (done) return; done = true; try { sock.destroy() } catch { /* */ } resolve(v) }
    sock.setTimeout(Math.min(timeoutMs, 3000))
    sock.once('timeout', () => finish(buf || ''))
    sock.once('error', () => finish(buf || null))
    sock.on('data', (d) => { buf += d.toString('latin1'); if (buf.length > 1024) finish(buf) })
    sock.once('close', () => finish(buf || null))
    try { sock.connect(port, ip) } catch { finish(null) }
  })
}
