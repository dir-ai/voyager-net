import dgram from 'node:dgram'
import type { NetFinding } from './types.js'

/**
 * UDP introspection (Kimi round-6 #4 — "the continent without TCP"). SNMP, NTP and DNS
 * live on UDP and a TCP-only scanner is blind to them. Read-only, one datagram each,
 * pinned to the vetted IP:
 *  - SNMP :161 — a public-community GET; a reply = the device answers to "public" (a
 *    classic full-config disclosure).
 *  - NTP :123 — a mode-7 monlist request; a reply = monlist enabled (a DDoS amplifier).
 *  - DNS :53 — a recursive query for a name we don't own; a recursive answer = an OPEN
 *    resolver (amplification + cache-poisoning surface).
 * Only enabled when the caller opts into UDP (it's connectionless — no "open port" state).
 */
export async function scanUdp(pin: string, host: string, timeoutMs: number): Promise<NetFinding[]> {
  const [snmp, ntp, dns] = await Promise.all([
    probe(pin, 161, snmpGetPublic(), timeoutMs),
    probe(pin, 123, ntpMonlist(), timeoutMs),
    probe(pin, 53, dnsRecursive(), timeoutMs),
  ])
  const out: NetFinding[] = []
  if (snmp && snmp.length > 2 && snmp[0] === 0x30) out.push({ severity: 'high', kind: 'snmp-public', detail: `SNMP on :161/udp answers the "public" community — device configuration is readable without credentials`, at: `${host}:161`, suggestedFix: 'disable SNMP or change the community string; prefer SNMPv3 with auth+priv; firewall :161/udp', confidence: 'strong' })
  if (ntp && ntp.length >= 4) out.push({ severity: 'medium', kind: 'ntp-monlist', detail: `NTP on :123/udp replied to a mode-7 monlist request — usable as a DDoS amplifier`, at: `${host}:123`, suggestedFix: 'disable monlist (noquery) / upgrade ntpd; rate-limit :123/udp', confidence: 'moderate' })
  if (dns && dns.length >= 4 && (dns[3] & 0x80) !== 0 && (dns[3] & 0x0f) === 0) out.push({ severity: 'medium', kind: 'open-resolver', detail: `DNS on :53/udp recursively resolved a name it is not authoritative for — an OPEN resolver (amplification + poisoning surface)`, at: `${host}:53`, suggestedFix: 'disable recursion for the public internet; restrict recursion to internal clients', confidence: 'moderate' })
  return out
}

function probe(ip: string, port: number, payload: Buffer, timeoutMs: number): Promise<Buffer | null> {
  return new Promise((resolve) => {
    const sock = dgram.createSocket(ip.includes(':') ? 'udp6' : 'udp4')
    let done = false
    const finish = (v: Buffer | null): void => { if (done) return; done = true; try { sock.close() } catch { /* */ } resolve(v) }
    const timer = setTimeout(() => finish(null), Math.min(timeoutMs, 4000))
    sock.once('message', (msg) => { clearTimeout(timer); finish(msg) })
    sock.once('error', () => { clearTimeout(timer); finish(null) })
    try { sock.send(payload, port, ip) } catch { clearTimeout(timer); finish(null) }
  })
}

/** SNMPv1 GET, community "public", OID 1.3.6.1.2.1.1.1.0 (sysDescr). */
function snmpGetPublic(): Buffer {
  return Buffer.from([
    0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // SEQ, ver=0, "public"
    0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, // GET, reqid, err, erridx
    0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00, // varbind sysDescr.0 (truncated OID ok for a liveness probe)
  ])
}
/** NTP mode-7 (private) monlist request. */
function ntpMonlist(): Buffer {
  const b = Buffer.alloc(8)
  b[0] = 0x17 // response=0, more=0, version=2, mode=7
  b[1] = 0x00; b[2] = 0x03; b[3] = 0x2a // impl=3 (XNTPD), req=42 (MON_GETLIST_1)
  return b
}
/** A recursive DNS query (RD=1) for a name the target won't be authoritative for. */
function dnsRecursive(): Buffer {
  const header = Buffer.from([0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) // RD=1, qd=1
  const qname = Buffer.concat([Buffer.from([0x01, 0x61]), Buffer.from([0x04]), Buffer.from('root', 'latin1'), Buffer.from([0x0a]), Buffer.from('servers', 'latin1'), Buffer.from([0x03]), Buffer.from('net', 'latin1'), Buffer.from([0x00])]) // a.root-servers.net
  const tail = Buffer.from([0x00, 0x01, 0x00, 0x01]) // A, IN
  return Buffer.concat([header, qname, tail])
}
