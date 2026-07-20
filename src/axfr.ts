import net from 'node:net'
import type { NetFinding } from './types.js'

/**
 * DNS zone-transfer (AXFR) detection (Kimi R3-9 / P0). A misconfigured authoritative
 * server that answers an AXFR hands out the ENTIRE zone — every subdomain, internal
 * host and record — to anyone. We send ONE AXFR query over TCP for the domain and
 * check whether the server returns zone records (ANCOUNT>0, RCODE=NoError) instead of
 * refusing. Read-only: a single standard query, no modification. Runs when :53 is open.
 */
export async function scanAxfr(pin: string, host: string, domain: string, port: number, timeoutMs: number): Promise<NetFinding[]> {
  const records = await tryAxfr(pin, port, domain, timeoutMs)
  if (records == null) return []
  if (records > 0) {
    return [{
      severity: 'high', kind: 'zone-transfer',
      detail: `DNS server on port ${port} allows AXFR zone transfer for ${domain} — it returned ${records}+ record(s), leaking the full internal zone (every subdomain/host) to anyone`,
      at: `${host}:${port}`, suggestedFix: 'restrict AXFR to your secondary name servers only (allow-transfer / TSIG); never allow it from the public internet', confidence: 'strong',
    }]
  }
  return []
}

/** Build + send an AXFR query over TCP; return the answer count, or null on error/refusal. */
function tryAxfr(ip: string, port: number, domain: string, timeoutMs: number): Promise<number | null> {
  return new Promise((resolve) => {
    const sock = new net.Socket()
    let buf = Buffer.alloc(0)
    let done = false
    const finish = (v: number | null): void => { if (done) return; done = true; try { sock.destroy() } catch { /* */ } resolve(v) }
    sock.setTimeout(timeoutMs)
    sock.once('timeout', () => finish(null))
    sock.once('error', () => finish(null))
    sock.once('connect', () => sock.write(axfrQuery(domain)))
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d])
      // TCP DNS: 2-byte length prefix, then the message. Wait for a full first message.
      if (buf.length < 2) return
      const msgLen = buf.readUInt16BE(0)
      if (buf.length < 2 + Math.min(msgLen, 12)) return
      const msg = buf.slice(2)
      if (msg.length < 12) return
      const rcode = msg.readUInt16BE(2) & 0x0f
      const ancount = msg.readUInt16BE(6)
      finish(rcode === 0 ? ancount : 0) // NoError + answers = transfer allowed
    })
    try { sock.connect(port, ip) } catch { finish(null) }
  })
}

function axfrQuery(domain: string): Buffer {
  const header = Buffer.alloc(12)
  header.writeUInt16BE(0x1234, 0) // id
  header.writeUInt16BE(0x0000, 2) // flags: standard query
  header.writeUInt16BE(1, 4) // qdcount
  const labels = domain.replace(/\.$/, '').split('.').filter(Boolean)
  const qname = Buffer.concat([...labels.map((l) => Buffer.concat([Buffer.from([Math.min(l.length, 63)]), Buffer.from(l.slice(0, 63), 'latin1')])), Buffer.from([0])])
  const qtail = Buffer.alloc(4)
  qtail.writeUInt16BE(252, 0) // QTYPE = AXFR
  qtail.writeUInt16BE(1, 2) // QCLASS = IN
  const msg = Buffer.concat([header, qname, qtail])
  const framed = Buffer.alloc(2 + msg.length)
  framed.writeUInt16BE(msg.length, 0)
  msg.copy(framed, 2)
  return framed
}
