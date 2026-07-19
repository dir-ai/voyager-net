import tls from 'node:tls'
import { stripInjection } from '@dir-ai/voyager'
import type { TlsInfo } from './types.js'

/** Inspect the TLS certificate + negotiated protocol of a port (read-only). */
export function inspectTls(host: string, port: number, timeoutMs = 6000): Promise<TlsInfo | null> {
  return new Promise((resolve) => {
    let settled = false
    const finish = (v: TlsInfo | null) => {
      if (settled) return
      settled = true
      resolve(v)
    }
    const socket = tls.connect(
      { host, port, servername: /^[a-z0-9.-]+$/i.test(host) ? host : undefined, rejectUnauthorized: false, timeout: timeoutMs },
      () => {
        try {
          const cert = socket.getPeerCertificate(false)
          const protocol = socket.getProtocol()
          const cipher = socket.getCipher()?.name ?? null
          const validTo = cert?.valid_to ? new Date(cert.valid_to) : null
          const days = validTo && !isNaN(validTo.getTime()) ? Math.round((validTo.getTime() - Date.now()) / 86_400_000) : null
          const issuerCN = cert?.issuer?.CN ? stripInjection(String(cert.issuer.CN)) : null
          const subjectCN = cert?.subject?.CN ? stripInjection(String(cert.subject.CN)) : null
          const altNames = (cert?.subjectaltname ?? '').split(',').map((s) => stripInjection(s.trim())).filter(Boolean).slice(0, 20)
          finish({
            port,
            protocol,
            cipher,
            issuer: issuerCN,
            subject: subjectCN,
            altNames,
            validFrom: cert?.valid_from ?? null,
            validTo: cert?.valid_to ?? null,
            daysToExpiry: days,
            selfSigned: issuerCN != null && subjectCN != null ? issuerCN === subjectCN : null,
          })
        } catch {
          finish(null)
        } finally {
          socket.destroy()
        }
      },
    )
    socket.once('timeout', () => { socket.destroy(); finish(null) })
    socket.once('error', () => finish(null))
  })
}
