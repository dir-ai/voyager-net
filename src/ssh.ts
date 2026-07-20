import net from 'node:net'
import { defang } from './fingerprint.js'
import type { NetFinding } from './types.js'

/**
 * SSH weak-algorithm detection (Kimi #4). Read-only: we exchange banners and read
 * the server's SSH_MSG_KEXINIT — which the server sends UNSOLICITED right after the
 * banner — then classify its advertised key-exchange, host-key, cipher and MAC
 * name-lists. No auth attempt, no session, no crafted exploit; just parsing what
 * the server volunteers. Weak algorithms (SHA-1 kex, ssh-rsa/ssh-dss host keys,
 * CBC/arcfour ciphers, MD5/SHA-1 MACs) are a downgrade / cryptanalysis surface.
 */
const WEAK = {
  kex: /(^|,)(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1|gss-group1-sha1|rsa1024-sha1)(,|$)/,
  hostKey: /(^|,)(ssh-rsa|ssh-dss|rsa-sha2-256-cert-v01)(,|$)/, // ssh-rsa = SHA-1 signature
  cipher: /(^|,)(3des-cbc|des-cbc|blowfish-cbc|cast128-cbc|arcfour|arcfour128|arcfour256|aes128-cbc|aes192-cbc|aes256-cbc|rijndael-cbc)/,
  mac: /(^|,)(hmac-md5|hmac-md5-96|hmac-sha1|hmac-sha1-96|umac-64|hmac-ripemd160)/,
}

export async function inspectSsh(pin: string, host: string, port: number, timeoutMs: number): Promise<NetFinding[]> {
  const kex = await readKexinit(pin, port, timeoutMs)
  if (!kex) return []
  const findings: NetFinding[] = []
  const at = `${host}:${port}`
  const flag = (list: string, re: RegExp, what: string, sev: NetFinding['severity']): void => {
    const weak = list.split(',').filter((a) => re.test(`,${a},`) || re.test(a))
    if (weak.length) findings.push({ severity: sev, kind: 'ssh-weak-algorithm', detail: `SSH offers weak ${what}: ${defang(weak.slice(0, 6).join(', '))}`, at, suggestedFix: `disable weak ${what} in sshd_config; keep modern algorithms only (e.g. curve25519, ssh-ed25519, chacha20-poly1305, hmac-sha2-256/512-etm)`, confidence: 'strong' })
  }
  flag(kex.kexAlgorithms, WEAK.kex, 'key-exchange (SHA-1 / weak group)', 'high')
  flag(kex.hostKeyAlgorithms, WEAK.hostKey, 'host-key algorithm (SHA-1 signature)', 'medium')
  flag(kex.ciphers, WEAK.cipher, 'cipher (CBC / arcfour)', 'high')
  flag(kex.macs, WEAK.mac, 'MAC (MD5 / SHA-1)', 'medium')
  return findings
}

interface Kexinit { kexAlgorithms: string; hostKeyAlgorithms: string; ciphers: string; macs: string }

function readKexinit(ip: string, port: number, timeoutMs: number): Promise<Kexinit | null> {
  return new Promise((resolve) => {
    const sock = new net.Socket()
    let buf = Buffer.alloc(0)
    let sentBanner = false
    let done = false
    const finish = (v: Kexinit | null): void => { if (done) return; done = true; try { sock.destroy() } catch { /* */ } resolve(v) }
    sock.setTimeout(timeoutMs)
    sock.once('timeout', () => finish(null))
    sock.once('error', () => finish(null))
    sock.once('connect', () => { /* wait for the server banner first */ })
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d])
      // The banner is line-based text ending in \r\n or \n; send ours once we see it.
      if (!sentBanner) {
        const nl = buf.indexOf(0x0a)
        if (nl < 0) { if (buf.length > 512) finish(null); return }
        if (!buf.slice(0, nl).toString('latin1').startsWith('SSH-')) return finish(null)
        sock.write('SSH-2.0-voyager_net\r\n')
        sentBanner = true
        buf = buf.slice(nl + 1) // drop the consumed banner; KEXINIT packet may follow
      }
      const k = parseKexinit(buf)
      if (k) finish(k)
      else if (buf.length > 65535) finish(null)
    })
    try { sock.connect(port, ip) } catch { finish(null) }
  })
}

/** Parse a binary SSH packet and, if it is SSH_MSG_KEXINIT (20), pull the four
 *  name-lists we care about. Returns null if not enough bytes yet / not a KEXINIT. */
function parseKexinit(buf: Buffer): Kexinit | null {
  if (buf.length < 6) return null
  const pktLen = buf.readUInt32BE(0)
  if (pktLen < 2 || pktLen > 65535) return null
  if (buf.length < 4 + pktLen) return null
  const padLen = buf.readUInt8(4)
  const payload = buf.slice(5, 4 + pktLen - padLen)
  if (payload.length < 17 || payload.readUInt8(0) !== 20) return null // 20 = SSH_MSG_KEXINIT
  let off = 17 // 1 (msg) + 16 (cookie)
  const nameList = (): string | null => {
    if (off + 4 > payload.length) return null
    const len = payload.readUInt32BE(off); off += 4
    if (off + len > payload.length) return null
    const s = payload.slice(off, off + len).toString('latin1'); off += len
    return s
  }
  const kexAlgorithms = nameList()
  const hostKeyAlgorithms = nameList()
  const ciphers = nameList() // encryption client→server
  nameList() // encryption server→client (same set in practice)
  const macs = nameList() // mac client→server
  if (kexAlgorithms == null || hostKeyAlgorithms == null || ciphers == null || macs == null) return null
  return { kexAlgorithms, hostKeyAlgorithms, ciphers, macs }
}
