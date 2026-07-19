import { lookup } from 'node:dns/promises'
import { parseTarget, blockedIpReason } from './authorize.js'
import { scanDns } from './dns.js'
import { scanPorts, DEFAULT_PORTS } from './ports.js'
import { inspectTls } from './tls.js'
import { inspectHttp } from './http.js'
import type { Confidence, NetBrief, NetFinding, ScanOptions } from './types.js'

const TLS_PORTS = new Set([443, 8443, 993, 995, 465, 5432])
const HTTP_PORTS = new Set([80, 8080, 3000])
const HTTPS_PORTS = new Set([443, 8443])
const SENSITIVE: Record<number, string> = { 23: 'telnet', 3306: 'mysql', 5432: 'postgres', 6379: 'redis', 27017: 'mongodb', 9200: 'elasticsearch', 5900: 'vnc', 3389: 'rdp', 445: 'smb' }

/**
 * Read-only, AUTHORIZED introspection of ONE host/domain: resolve once + pin the
 * IP (anti DNS-rebinding), probe ports (real states), passively fingerprint
 * services, inspect TLS depth + HTTP hygiene → findings with described fixes.
 */
export async function scan(input: string, opts: ScanOptions = {}): Promise<NetBrief> {
  const log = opts.onLog ?? (() => {})
  const t = parseTarget(input)

  const base = (): NetBrief => ({
    target: { input, host: t.host, kind: t.kind, scope: t.scope }, resolvedIp: null,
    authorized: opts.authorized === true, summary: '', dns: null, ports: [], tls: [], http: [], findings: [],
    confidence: 'weak', suggestedNextProbes: [], sanitization: { framedFields: 0 }, notes: [],
  })

  if (!t.ok) return { ...base(), error: `invalid target: ${t.reason}` }
  const host = t.host!

  if (opts.authorized !== true) {
    return { ...base(), error: 'not authorized. voyager-net only scans hosts you OWN or are explicitly permitted to test. Re-run with --authorized (CLI) / authorized:true (MCP). Scanning third-party infrastructure without permission may be illegal.' }
  }

  const timeoutMs = Math.min(Math.max(opts.timeoutMs ?? 3000, 500), 15_000)
  const ports = (opts.ports && opts.ports.length ? opts.ports : DEFAULT_PORTS).filter((p) => Number.isInteger(p) && p > 0 && p < 65536).slice(0, 64)

  // ── Resolve ONCE and pin (anti-rebinding). All connections use this IP. ──────
  let resolvedIp: string | null = t.kind === 'ip' ? host : null
  if (t.kind === 'domain') {
    try {
      resolvedIp = (await lookup(host)).address
    } catch {
      return { ...base(), error: `could not resolve ${host}` }
    }
    const blocked = blockedIpReason(resolvedIp)
    if (blocked) return { ...base(), resolvedIp, error: `${host} ${blocked}` }
  }
  const pin = resolvedIp ?? host

  const dns = t.kind === 'domain' ? await (log('resolving DNS…'), scanDns(host, timeoutMs)) : null

  log(`probing ${ports.length} ports…`)
  const portResults = await scanPorts(pin, ports, timeoutMs)
  const open = portResults.filter((p) => p.state === 'open')

  log('inspecting TLS + HTTP…')
  const tlsInfos = (await Promise.all(open.filter((p) => TLS_PORTS.has(p.port)).map((p) => inspectTls(pin, p.port, host, timeoutMs + 3000)))).filter(Boolean) as NonNullable<Awaited<ReturnType<typeof inspectTls>>>[]
  const httpInfos = (await Promise.all(open.filter((p) => HTTP_PORTS.has(p.port) || HTTPS_PORTS.has(p.port)).map((p) => inspectHttp(host, p.port, HTTPS_PORTS.has(p.port), timeoutMs + 3000)))).filter(Boolean) as NonNullable<Awaited<ReturnType<typeof inspectHttp>>>[]

  // ── Findings ────────────────────────────────────────────────────────────────
  const findings: NetFinding[] = []

  for (const p of open) {
    if (SENSITIVE[p.port]) {
      findings.push({ severity: t.scope === 'public' ? 'high' : 'medium', kind: 'exposed-service', detail: `${p.product ?? SENSITIVE[p.port]}${p.version ? ` ${p.version}` : ''} (port ${p.port}) reachable${t.scope === 'public' ? ' from a PUBLIC address' : ''}`, at: `${host}:${p.port}`, suggestedFix: `restrict ${SENSITIVE[p.port]} to a private network / VPN / security group`, confidence: 'strong' })
    }
    if (p.product && p.version) {
      findings.push({ severity: 'info', kind: 'service-version', detail: `${p.product} ${p.version} identified (banner)`, at: `${host}:${p.port}`, suggestedFix: `check ${p.product} ${p.version} against your CVE feed (OSV/NVD); update if a fix exists`, confidence: 'moderate' })
    }
  }

  for (const c of tlsInfos) {
    const weak = c.supportedProtocols.filter((p) => p === 'TLSv1' || p === 'TLSv1.1')
    if (weak.length) findings.push({ severity: 'high', kind: 'weak-tls', detail: `accepts deprecated ${weak.join(' + ')}`, at: `${host}:${c.port}`, suggestedFix: 'disable TLS 1.0/1.1; require TLS 1.2+ (ideally 1.3)', confidence: 'strong' })
    if (c.daysToExpiry != null && c.daysToExpiry < 0) findings.push({ severity: 'critical', kind: 'tls-expired', detail: `certificate EXPIRED ${-c.daysToExpiry}d ago`, at: `${host}:${c.port}`, suggestedFix: 'renew the certificate immediately (ACME)', confidence: 'strong' })
    else if (c.daysToExpiry != null && c.daysToExpiry < 21) findings.push({ severity: c.daysToExpiry < 7 ? 'high' : 'medium', kind: 'tls-expiring', detail: `certificate expires in ${c.daysToExpiry}d`, at: `${host}:${c.port}`, suggestedFix: 'renew now and automate renewal (ACME)', confidence: 'strong' })
    if (c.trusted === false && c.selfSigned) findings.push({ severity: 'medium', kind: 'tls-untrusted', detail: 'certificate not trusted by the system store (self-signed)', at: `${host}:${c.port}`, suggestedFix: 'use a CA-issued certificate for a public endpoint', confidence: 'moderate' })
    if (c.keyBits != null && c.keyBits > 0 && c.keyBits < 2048) findings.push({ severity: 'medium', kind: 'weak-key', detail: `${c.keyBits}-bit key (below 2048)`, at: `${host}:${c.port}`, suggestedFix: 'reissue with a ≥2048-bit RSA or an EC key', confidence: 'strong' })
  }

  for (const h of httpInfos) {
    if (h.url.startsWith('https') && !h.securityHeaders['strict-transport-security']) findings.push({ severity: 'medium', kind: 'missing-hsts', detail: 'HTTPS without HSTS', at: h.url, suggestedFix: 'add `Strict-Transport-Security: max-age=63072000; includeSubDomains`', confidence: 'strong' })
    if (h.cors === '*') findings.push({ severity: 'medium', kind: 'cors-wildcard', detail: 'Access-Control-Allow-Origin: * (any origin)', at: h.url, suggestedFix: 'restrict CORS to the specific trusted origin(s)', confidence: 'strong' })
    if (h.cookies && (!h.cookies.secure || !h.cookies.httpOnly)) findings.push({ severity: 'low', kind: 'weak-cookie', detail: `cookie missing ${[!h.cookies.secure && 'Secure', !h.cookies.httpOnly && 'HttpOnly'].filter(Boolean).join(' + ')}`, at: h.url, suggestedFix: 'set Secure + HttpOnly (and SameSite) on session cookies', confidence: 'strong' })
    if (!h.securityHeaders['content-security-policy']) findings.push({ severity: 'low', kind: 'missing-csp', detail: 'no Content-Security-Policy', at: h.url, suggestedFix: 'add a Content-Security-Policy', confidence: 'moderate' })
  }
  for (const h of httpInfos) if (h.url.startsWith('http://') && !h.redirectsToHttps) findings.push({ severity: 'low', kind: 'no-https-redirect', detail: 'plain HTTP does not redirect to HTTPS', at: h.url, suggestedFix: 'redirect all HTTP to HTTPS (301)', confidence: 'strong' })

  if (dns) {
    if (dns.mx.length && !dns.hasSpf) findings.push({ severity: 'medium', kind: 'missing-spf', detail: 'sends mail (MX) but no SPF record', at: host, suggestedFix: 'publish an SPF TXT record', confidence: 'strong' })
    if (dns.mx.length && !dns.hasDmarc) findings.push({ severity: 'medium', kind: 'missing-dmarc', detail: 'no DMARC record', at: host, suggestedFix: 'publish `v=DMARC1; p=quarantine; …`', confidence: 'strong' })
    if (!dns.hasCaa) findings.push({ severity: 'low', kind: 'missing-caa', detail: 'no CAA record — any CA may issue certs', at: host, suggestedFix: 'add a CAA record pinning your CA(s)', confidence: 'moderate' })
  }

  // ── Summary + confidence + next probes ──────────────────────────────────────
  const worst = ['critical', 'high', 'medium', 'low', 'info'].find((s) => findings.some((f) => f.severity === s))
  const summary = findings.length
    ? `${host}${resolvedIp && resolvedIp !== host ? ` (${resolvedIp})` : ''} — ${findings.length} finding(s); worst: ${worst}. ${open.length} open port(s).`
    : `${host} — no issues across ${ports.length} ports${dns ? ' + DNS' : ''}. ${open.length} open port(s).`

  const framedFields = tlsInfos.length + httpInfos.filter((h) => h.server).length + open.filter((p) => p.banner).length
  const signals = [dns != null, open.length > 0, tlsInfos.length > 0].filter(Boolean).length
  const confidence: Confidence = signals >= 2 ? 'strong' : signals === 1 ? 'moderate' : 'weak'

  const suggestedNextProbes: string[] = []
  const versioned = open.filter((p) => p.product && p.version)
  if (versioned.length) suggestedNextProbes.push(`match ${versioned.map((p) => `${p.product} ${p.version}`).join(', ')} against a CVE feed`)
  const filtered = portResults.filter((p) => p.state === 'filtered')
  if (filtered.length) suggestedNextProbes.push(`${filtered.length} port(s) filtered (firewalled) — probe from an internal vantage point to confirm what is really open`)
  if (open.some((p) => HTTP_PORTS.has(p.port) || HTTPS_PORTS.has(p.port))) suggestedNextProbes.push('review the web app surface (auth, API endpoints) — out of scope for a network sense')

  return {
    target: { input, host, kind: t.kind, scope: t.scope }, resolvedIp,
    authorized: true, summary, dns, ports: portResults, tls: tlsInfos, http: httpInfos, findings,
    confidence, suggestedNextProbes, sanitization: { framedFields }, notes: [],
  }
}
