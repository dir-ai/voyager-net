import net from 'node:net'
import ipaddr from 'ipaddr.js'

export interface TargetDecision {
  ok: boolean
  host: string | null
  kind: 'ip' | 'domain' | 'invalid'
  scope: 'loopback' | 'private' | 'public' | 'unknown'
  reason?: string
}

// Cloud instance-metadata endpoints that sit in otherwise-routable ranges (a
// pure range check wouldn't catch them). Most metadata (169.254.169.254
// link-local, fd00:ec2::254 ULA, 100.100.100.200 CGNAT) is already covered by the
// range classifier below; this set is defense-in-depth for the routable ones.
const METADATA_HOSTS = new Set(['169.254.169.254', 'fd00:ec2::254', 'metadata.google.internal', '100.100.100.200'])

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i

/**
 * Parse and vet a SINGLE target. voyager-net deliberately refuses anything that
 * enables mass or ambiguous scanning: CIDR blocks, ranges, comma lists, ports in
 * the target, wildcards, and URLs. One host or one domain, or nothing. A literal
 * IP is classified immediately (loopback/private/metadata refused); IPv6 literals
 * are accepted (bracketed or bare).
 */
export function parseTarget(input: string): TargetDecision {
  const raw = (input ?? '').trim()
  if (!raw) return { ok: false, host: null, kind: 'invalid', scope: 'unknown', reason: 'empty target' }
  const bad = (reason: string): TargetDecision => ({ ok: false, host: null, kind: 'invalid', scope: 'unknown', reason })
  // Lists, whitespace, CIDR, ranges (10.0.0.1-50), wildcards → more than one host.
  if (/[\s,]/.test(raw) || raw.includes('/') || /\.\./.test(raw) || raw.includes('*') || /\.\d{1,3}-\d/.test(raw)) {
    return bad('only a single host or domain is allowed — no CIDR ranges, lists, wildcards, or URLs')
  }

  // Extract the host, allowing a bracketed IPv6 literal, but rejecting an explicit
  // port in the target. IPv6 colons must NOT be miscounted as a host:port split.
  let host = raw
  let hadPort = false
  const bracket = /^\[([0-9a-f:]+)\](?::(\d+))?$/i.exec(raw)
  if (bracket) {
    host = bracket[1]
    hadPort = bracket[2] != null
  } else if (net.isIP(raw)) {
    host = raw // bare IPv4 or IPv6 literal
  } else if (/^[^:]+:\d+$/.test(raw)) {
    host = raw.slice(0, raw.lastIndexOf(':'))
    hadPort = true
  }
  if (hadPort) return bad('do not include a port in the target — voyager-net probes a fixed service set')

  if (METADATA_HOSTS.has(host.toLowerCase())) return bad('cloud metadata endpoints are blocked (SSRF/credential-theft surface)')

  const ipVer = net.isIP(host)
  if (ipVer) {
    // A LITERAL IP the user typed (with --authorized) may legitimately be a
    // private/loopback host on their own network — internal audits are allowed.
    // Only metadata / link-local / unspecified are refused even when explicit.
    const blocked = literalTargetBlockReason(host)
    if (blocked) return bad(`${host} ${blocked}`)
    return { ok: true, host, kind: 'ip', scope: ipScopeOf(host) }
  }
  if (DOMAIN_RE.test(host)) return { ok: true, host, kind: 'domain', scope: 'unknown' }
  return bad(`not a valid single host or domain: ${host}`)
}

/** For an explicitly-typed literal IP target: block only the addresses that are
 *  never a legitimate audit target and are the SSRF-adjacent ones (cloud metadata,
 *  link-local, unspecified/broadcast/multicast/reserved). PRIVATE, LOOPBACK, and
 *  CGNAT literals are permitted — the user asserted authorization for their own
 *  internal host. (The stricter `blockedIpReason` still guards the RESOLVED path,
 *  where a public domain pointing at an internal IP is a rebinding attack.) */
function literalTargetBlockReason(ipStr: string): string | null {
  let addr: ipaddr.IPv4 | ipaddr.IPv6
  try {
    addr = ipaddr.parse(ipStr)
  } catch {
    return `is an unparseable IP (${ipStr})`
  }
  if (addr.kind() === 'ipv6') {
    const v6 = addr as ipaddr.IPv6
    if (v6.isIPv4MappedAddress()) addr = v6.toIPv4Address()
  }
  if (METADATA_HOSTS.has(addr.toString())) return 'is a cloud metadata endpoint (SSRF/credential-theft surface)'
  const range = addr.range()
  if (['linkLocal', 'unspecified', 'broadcast', 'multicast', 'reserved'].includes(range)) return `is a non-routable/link-local address (${range})`
  return null
}

/**
 * Classify a resolved IP and return a reason if it must not be probed. Parses the
 * address canonically (ipaddr.js), unwraps IPv4-mapped IPv6 to the embedded IPv4,
 * and refuses anything that is not a normal PUBLIC unicast address — closing
 * IPv4-mapped bypasses (::ffff:169.254.169.254), unspecified (0.0.0.0, ::),
 * loopback, CGNAT (100.64/10), NAT64, link-local, private, reserved, multicast.
 * Applied AFTER DNS resolution (anti-rebinding) and to literal IP targets alike.
 */
export function blockedIpReason(ipStr: string): string | null {
  let addr: ipaddr.IPv4 | ipaddr.IPv6
  try {
    addr = ipaddr.parse(ipStr)
  } catch {
    return `is an unparseable IP (${ipStr})`
  }
  if (addr.kind() === 'ipv6') {
    const v6 = addr as ipaddr.IPv6
    if (v6.isIPv4MappedAddress()) addr = v6.toIPv4Address()
  }
  if (METADATA_HOSTS.has(addr.toString())) return 'is a cloud metadata endpoint (SSRF/credential-theft surface)'
  const range = addr.range()
  if (range !== 'unicast') return `is a non-public address (${range})`
  return null
}

function ipScopeOf(ipStr: string): TargetDecision['scope'] {
  try {
    let addr = ipaddr.parse(ipStr)
    if (addr.kind() === 'ipv6') {
      const v6 = addr as ipaddr.IPv6
      if (v6.isIPv4MappedAddress()) addr = v6.toIPv4Address()
    }
    const r = addr.range()
    if (r === 'loopback') return 'loopback'
    if (r === 'unicast') return 'public'
    return 'private'
  } catch {
    return 'unknown'
  }
}
