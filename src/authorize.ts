import net from 'node:net'

export interface TargetDecision {
  ok: boolean
  host: string | null
  kind: 'ip' | 'domain' | 'invalid'
  scope: 'loopback' | 'private' | 'public' | 'unknown'
  reason?: string
}

// Cloud instance-metadata endpoints — probing these is an SSRF/credential-theft
// vector, never a legitimate ops check. Hard-blocked regardless of authorization.
const METADATA_HOSTS = new Set(['169.254.169.254', 'fd00:ec2::254', 'metadata.google.internal', '100.100.100.200'])

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i

/**
 * Parse and vet a SINGLE target. voyager-net deliberately refuses anything that
 * enables mass or ambiguous scanning: CIDR blocks, ranges, comma lists, ports in
 * the target, wildcards, and URLs. One host or one domain, or nothing.
 */
export function parseTarget(input: string): TargetDecision {
  const raw = (input ?? '').trim()
  if (!raw) return { ok: false, host: null, kind: 'invalid', scope: 'unknown', reason: 'empty target' }
  // Refuse anything that could describe MORE than one host.
  if (/[/,]|\s|\.\.|-\d{1,3}\.|\*/.test(raw) || raw.split(':').length > 2) {
    return { ok: false, host: null, kind: 'invalid', scope: 'unknown', reason: 'only a single host or domain is allowed — no CIDR ranges, lists, wildcards, or URLs' }
  }
  const host = raw.replace(/^\[|\]$/g, '') // strip IPv6 brackets

  if (METADATA_HOSTS.has(host.toLowerCase())) {
    return { ok: false, host, kind: 'invalid', scope: 'unknown', reason: 'cloud metadata endpoints are blocked (SSRF/credential-theft surface)' }
  }

  const ipVer = net.isIP(host)
  if (ipVer) {
    return { ok: true, host, kind: 'ip', scope: ipScope(host, ipVer) }
  }
  if (DOMAIN_RE.test(host)) {
    return { ok: true, host, kind: 'domain', scope: 'unknown' }
  }
  return { ok: false, host: null, kind: 'invalid', scope: 'unknown', reason: `not a valid single host or domain: ${host}` }
}

function ipScope(ip: string, ver: number): TargetDecision['scope'] {
  if (ver === 4) {
    if (ip === '127.0.0.1' || ip.startsWith('127.')) return 'loopback'
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) || ip.startsWith('169.254.')) return 'private'
    return 'public'
  }
  if (ip === '::1') return 'loopback'
  if (/^(fe80|fc|fd)/i.test(ip)) return 'private'
  return 'public'
}
