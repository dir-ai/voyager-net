import net from 'node:net'
import type { NetFinding, PortResult } from './types.js'

/**
 * VNC auth-none detection (Kimi R3-1). RFB is stateful: the server sends a version
 * banner ("RFB 003.008\n"), the client echoes a version, then the server lists the
 * security types it will accept. Security type 1 = "None" = no password. We do only
 * that handshake (no framebuffer, no input) and flag a server that offers None.
 * Runs on any open port speaking RFB (5900/5901 or a dark port), so VNC on an
 * arbitrary port is caught. Read-only, pinned to the vetted IP.
 */
export async function scanVnc(pin: string, host: string, open: PortResult[], inspected: Set<number>, timeoutMs: number): Promise<NetFinding[]> {
  const targets = open.filter((p) => p.port === 5900 || p.port === 5901 || /vnc|rfb/i.test(`${p.product ?? ''} ${p.banner ?? ''}`) || (!p.product && !inspected.has(p.port)))
  const out = await Promise.all(targets.map((p) => probeVnc(pin, host, p.port, timeoutMs)))
  return out.filter(Boolean) as NetFinding[]
}

function probeVnc(pin: string, host: string, port: number, timeoutMs: number): Promise<NetFinding | null> {
  return new Promise((resolve) => {
    const sock = new net.Socket()
    let buf = Buffer.alloc(0)
    let sentVersion = false
    let done = false
    const at = `${host}:${port}`
    const finish = (v: NetFinding | null): void => { if (done) return; done = true; try { sock.destroy() } catch { /* */ } resolve(v) }
    sock.setTimeout(timeoutMs)
    sock.once('timeout', () => finish(null))
    sock.once('error', () => finish(null))
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d])
      // Stage 1: the RFB version banner (12 bytes, "RFB 003.00x\n").
      if (!sentVersion) {
        if (buf.length < 12) return
        if (!buf.slice(0, 4).toString('latin1').startsWith('RFB ')) return finish(null)
        sock.write(buf.slice(0, 12)) // echo the server's version — negotiate at its level
        sentVersion = true
        buf = buf.slice(12)
        return
      }
      // Stage 2: security types. v3.7+: [count][types…]; v3.3: a 4-byte type.
      if (buf.length >= 1) {
        const count = buf.readUInt8(0)
        let none = false
        if (count > 0 && count <= 32 && buf.length >= 1 + count) none = [...buf.slice(1, 1 + count)].includes(1)
        else if (buf.length >= 4) none = buf.readUInt32BE(0) === 1 // v3.3 direct type
        else return // wait for more
        if (none) {
          return finish({ severity: 'critical', kind: 'unauthenticated-service', detail: `VNC (RFB) on port ${port} offers security type "None" — the desktop is remotely controllable WITHOUT a password`, at, suggestedFix: 'require VNC authentication (or better, tunnel VNC over SSH/VPN) and firewall the port', confidence: 'strong' })
        }
        return finish({ severity: 'info', kind: 'service-auth-ok', detail: `VNC (RFB) on port ${port} requires authentication (no None type offered)`, at, suggestedFix: 'no action — password-protected', confidence: 'moderate' })
      }
    })
    try { sock.connect(port, pin) } catch { finish(null) }
  })
}
