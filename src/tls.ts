import tls from 'node:tls'
import { stripInjection } from '@dir-ai/voyager'
import type { TlsInfo } from './types.js'

const PROTOS: Array<{ label: string; min: tls.SecureVersion; max: tls.SecureVersion }> = [
  { label: 'TLSv1', min: 'TLSv1', max: 'TLSv1' },
  { label: 'TLSv1.1', min: 'TLSv1.1', max: 'TLSv1.1' },
  { label: 'TLSv1.2', min: 'TLSv1.2', max: 'TLSv1.2' },
  { label: 'TLSv1.3', min: 'TLSv1.3', max: 'TLSv1.3' },
]

// Valid SNI only for a real hostname (not an IP): connecting to a pinned IP while
// still sending the original hostname as SNI is exactly how you pin an IP safely.
const sniOf = (servername: string) => (/[a-z]/i.test(servername) && !/^\d+\.\d+\.\d+\.\d+$/.test(servername) ? servername : undefined)

/** Does the endpoint ACCEPT a specific TLS version? One short read-only handshake. */
function probeProtocol(ip: string, port: number, servername: string, p: (typeof PROTOS)[number], timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    let done = false
    const fin = (v: boolean) => { if (!done) { done = true; resolve(v) } }
    let s: tls.TLSSocket
    try {
      // For the DEPRECATED versions, drop the local OpenSSL security level so our
      // OWN OpenSSL 3 build doesn't refuse the handshake first ("legacy sigalg
      // disallowed") — otherwise we'd report a server that STILL accepts TLS 1.0/1.1
      // as clean. We only ask; the server decides. Modern versions keep the default.
      const weak = p.min === 'TLSv1' || p.min === 'TLSv1.1'
      s = tls.connect({ host: ip, port, servername: sniOf(servername), rejectUnauthorized: false, minVersion: p.min, maxVersion: p.max, timeout: timeoutMs, ...(weak ? { ciphers: 'DEFAULT@SECLEVEL=0' } : {}) }, () => { s.destroy(); fin(true) })
    } catch { return fin(false) }
    s.once('error', () => fin(false))
    s.once('timeout', () => { s.destroy(); fin(false) })
  })
}

/** Is the chain trusted by the system store for this hostname? (rejectUnauthorized) */
function probeTrust(ip: string, port: number, servername: string, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    let done = false
    const fin = (v: boolean) => { if (!done) { done = true; resolve(v) } }
    let s: tls.TLSSocket
    try {
      s = tls.connect({ host: ip, port, servername: sniOf(servername), rejectUnauthorized: true, timeout: timeoutMs }, () => { s.destroy(); fin(true) })
    } catch { return fin(false) }
    s.once('error', () => fin(false))
    s.once('timeout', () => { s.destroy(); fin(false) })
  })
}

/** Inspect TLS: connect to the pinned `ip` but present `servername` (SNI = the
 *  real hostname). Certificate posture + accepted protocol versions + chain trust,
 *  all via read-only handshakes. */
export async function inspectTls(ip: string, port: number, servername: string, timeoutMs = 6000): Promise<TlsInfo | null> {
  const base = await new Promise<TlsInfo | null>((resolve) => {
    let settled = false
    const finish = (v: TlsInfo | null) => { if (!settled) { settled = true; resolve(v) } }
    // TOLERANT base handshake (Kimi Canto VI #21 — the reverse gate). A server that
    // accepts ONLY TLS 1.0/1.1 (or only a legacy cipher) REFUSES a modern-default
    // connect — and the old code did `if (!base) return null`, so the WORST server
    // (legacy-only) became INVISIBLE: the protocol enumeration below never ran and no
    // `weak-tls` finding fired. We now offer down to TLSv1 with SECLEVEL=0 so the base
    // handshake SUCCEEDS against a legacy-only endpoint too. A modern server still
    // negotiates its HIGHEST version (server preference wins; DEFAULT orders strong
    // suites first), so the protocol/cipher we read is unchanged for it — only a
    // legacy-only server now yields a (correctly bad) TlsInfo instead of nothing.
    const socket = tls.connect({ host: ip, port, servername: sniOf(servername), rejectUnauthorized: false, minVersion: 'TLSv1', ciphers: 'DEFAULT@SECLEVEL=0', timeout: timeoutMs }, () => {
      try {
        const cert = socket.getPeerCertificate(false)
        const validTo = cert?.valid_to ? new Date(cert.valid_to) : null
        const days = validTo && !isNaN(validTo.getTime()) ? Math.floor((validTo.getTime() - Date.now()) / 86_400_000) : null
        const issuerCN = cert?.issuer?.CN ? stripInjection(String(cert.issuer.CN)) : null
        const subjectCN = cert?.subject?.CN ? stripInjection(String(cert.subject.CN)) : null
        finish({
          port, protocol: socket.getProtocol(), cipher: socket.getCipher()?.name ?? null,
          issuer: issuerCN, subject: subjectCN,
          altNames: (cert?.subjectaltname ?? '').split(',').map((s) => stripInjection(s.trim())).filter(Boolean).slice(0, 20),
          validFrom: cert?.valid_from ?? null, validTo: cert?.valid_to ?? null, daysToExpiry: days,
          selfSigned: issuerCN != null && subjectCN != null ? issuerCN === subjectCN : null,
          supportedProtocols: [], trusted: null,
          // keyBits is only meaningful for RSA (the <2048 rule). EC keys have small
          // bit counts BY DESIGN (P-256 ≈ RSA-3072), so report null for them to
          // avoid a false "weak key" on a strong EC certificate.
          keyBits: (cert?.asn1Curve || cert?.nistCurve) ? null : typeof cert?.bits === 'number' ? cert.bits : null,
        })
      } catch { finish(null) } finally { socket.destroy() }
    })
    socket.once('timeout', () => { socket.destroy(); finish(null) })
    socket.once('error', () => finish(null))
  })
  if (!base) return null

  const supported: string[] = []
  for (const p of PROTOS) if (await probeProtocol(ip, port, servername, p, Math.min(timeoutMs, 5000))) supported.push(p.label)
  base.supportedProtocols = supported
  base.trusted = await probeTrust(ip, port, servername, Math.min(timeoutMs, 5000))
  return base
}
