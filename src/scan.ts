import { parseTarget } from './authorize.js'
import { scanDns } from './dns.js'
import { scanPorts, DEFAULT_PORTS } from './ports.js'
import { inspectTls } from './tls.js'
import { inspectHttp } from './http.js'
import type { Confidence, NetBrief, NetFinding, ScanOptions } from './types.js'

// Ports we speak TLS on / HTTP on when open.
const TLS_PORTS = new Set([443, 8443, 993, 995, 465, 5432])
const HTTP_PORTS = new Set([80, 8080, 3000])
const HTTPS_PORTS = new Set([443, 8443])
// Services that should almost never face the public internet unauthenticated.
const SENSITIVE: Record<number, string> = { 23: 'telnet', 3306: 'mysql', 5432: 'postgres', 6379: 'redis', 27017: 'mongodb', 9200: 'elasticsearch', 5900: 'vnc', 3389: 'rdp', 445: 'smb' }

/**
 * Read-only, AUTHORIZED introspection of ONE host/domain: DNS + ports + TLS +
 * HTTP hygiene → findings with described (never applied) fixes. Refuses unless
 * `authorized` is set, refuses ranges/CIDR/metadata endpoints, never exploits,
 * never floods.
 */
export async function scan(input: string, opts: ScanOptions = {}): Promise<NetBrief> {
  const log = opts.onLog ?? (() => {})
  const t = parseTarget(input)

  const base = (): NetBrief => ({
    target: { input, host: t.host, kind: t.kind, scope: t.scope },
    authorized: opts.authorized === true,
    summary: '', dns: null, ports: [], tls: [], http: [], findings: [],
    confidence: 'weak', sanitization: { framedFields: 0 }, notes: [],
  })

  if (!t.ok) return { ...base(), error: `invalid target: ${t.reason}` }
  const host = t.host!

  // ── The authorization gate — fail-closed ────────────────────────────────────
  if (opts.authorized !== true) {
    return {
      ...base(),
      error: 'not authorized. voyager-net only scans hosts you OWN or are explicitly permitted to test. Re-run with --authorized (CLI) / authorized:true (MCP) to assert that. Scanning third-party infrastructure without permission may be illegal.',
    }
  }

  const timeoutMs = Math.min(Math.max(opts.timeoutMs ?? 3000, 500), 15_000)
  const ports = (opts.ports && opts.ports.length ? opts.ports : DEFAULT_PORTS).filter((p) => Number.isInteger(p) && p > 0 && p < 65536).slice(0, 64)

  // ── DNS (domains only) ──────────────────────────────────────────────────────
  const dns = t.kind === 'domain' ? await (log('resolving DNS…'), scanDns(host, timeoutMs)) : null

  // ── Ports ───────────────────────────────────────────────────────────────────
  log(`probing ${ports.length} ports…`)
  const portResults = await scanPorts(host, ports, timeoutMs)
  const open = portResults.filter((p) => p.open)

  // ── TLS + HTTP on the open ports that speak them ────────────────────────────
  log('inspecting TLS + HTTP on open ports…')
  const tlsInfos = (await Promise.all(open.filter((p) => TLS_PORTS.has(p.port)).map((p) => inspectTls(host, p.port, timeoutMs + 3000)))).filter(Boolean) as NonNullable<Awaited<ReturnType<typeof inspectTls>>>[]
  const httpInfos = (await Promise.all(
    open
      .filter((p) => HTTP_PORTS.has(p.port) || HTTPS_PORTS.has(p.port))
      .map((p) => inspectHttp(host, p.port, HTTPS_PORTS.has(p.port), timeoutMs + 3000)),
  )).filter(Boolean) as NonNullable<Awaited<ReturnType<typeof inspectHttp>>>[]

  // ── Findings ────────────────────────────────────────────────────────────────
  const findings: NetFinding[] = []

  for (const p of open) {
    if (SENSITIVE[p.port]) {
      findings.push({
        severity: t.scope === 'public' ? 'high' : 'medium',
        kind: 'exposed-service',
        detail: `${SENSITIVE[p.port]} (port ${p.port}) is reachable${t.scope === 'public' ? ' from a PUBLIC address' : ''}`,
        at: `${host}:${p.port}`,
        suggestedFix: `restrict ${SENSITIVE[p.port]} to a private network / VPN / security group; do not expose it publicly`,
        confidence: 'strong',
      })
    }
  }

  for (const c of tlsInfos) {
    if (c.daysToExpiry != null && c.daysToExpiry < 0) {
      findings.push({ severity: 'critical', kind: 'tls-expired', detail: `certificate EXPIRED ${-c.daysToExpiry}d ago`, at: `${host}:${c.port}`, suggestedFix: 'renew the certificate immediately (certbot/ACME or your CA)', confidence: 'strong' })
    } else if (c.daysToExpiry != null && c.daysToExpiry < 21) {
      findings.push({ severity: c.daysToExpiry < 7 ? 'high' : 'medium', kind: 'tls-expiring', detail: `certificate expires in ${c.daysToExpiry}d`, at: `${host}:${c.port}`, suggestedFix: 'renew now and automate renewal (ACME) so it never lapses', confidence: 'strong' })
    }
    if (c.selfSigned === true) {
      findings.push({ severity: 'medium', kind: 'tls-self-signed', detail: 'self-signed certificate', at: `${host}:${c.port}`, suggestedFix: 'use a CA-issued (e.g. Let’s Encrypt) certificate for a public endpoint', confidence: 'moderate' })
    }
    if (c.protocol && /TLSv1(\.[01])?$/.test(c.protocol)) {
      findings.push({ severity: 'high', kind: 'weak-tls', detail: `negotiated ${c.protocol} (deprecated)`, at: `${host}:${c.port}`, suggestedFix: 'disable TLS 1.0/1.1; require TLS 1.2+ (ideally 1.3)', confidence: 'strong' })
    }
  }

  for (const h of httpInfos) {
    const missing = Object.entries(h.securityHeaders).filter(([, present]) => !present).map(([k]) => k)
    if (h.url.startsWith('https') && !h.securityHeaders['strict-transport-security']) {
      findings.push({ severity: 'medium', kind: 'missing-hsts', detail: 'HTTPS without HSTS (Strict-Transport-Security)', at: h.url, suggestedFix: 'add `Strict-Transport-Security: max-age=63072000; includeSubDomains`', confidence: 'strong' })
    }
    if (!h.securityHeaders['content-security-policy']) {
      findings.push({ severity: 'low', kind: 'missing-csp', detail: 'no Content-Security-Policy header', at: h.url, suggestedFix: 'add a Content-Security-Policy to reduce XSS/injection blast radius', confidence: 'moderate' })
    }
    if (missing.length >= 4) {
      findings.push({ severity: 'info', kind: 'header-hygiene', detail: `${missing.length} security headers missing: ${missing.join(', ')}`, at: h.url, suggestedFix: 'set the standard security-header baseline', confidence: 'moderate' })
    }
  }

  if (dns) {
    if (dns.mx.length && !dns.hasSpf) findings.push({ severity: 'medium', kind: 'missing-spf', detail: 'domain sends mail (MX) but has no SPF record', at: host, suggestedFix: 'publish an SPF TXT record (`v=spf1 …`) to curb spoofing', confidence: 'strong' })
    if (dns.mx.length && !dns.hasDmarc) findings.push({ severity: 'medium', kind: 'missing-dmarc', detail: 'no DMARC record (`_dmarc`)', at: host, suggestedFix: 'publish a DMARC policy (`v=DMARC1; p=quarantine; …`)', confidence: 'strong' })
    if (!dns.hasCaa) findings.push({ severity: 'low', kind: 'missing-caa', detail: 'no CAA record — any CA may issue certs for this domain', at: host, suggestedFix: 'add a CAA record pinning your CA(s)', confidence: 'moderate' })
  }

  // ── Summary + confidence ────────────────────────────────────────────────────
  const bySev = (s: string) => findings.filter((f) => f.severity === s).length
  const worst = ['critical', 'high', 'medium', 'low', 'info'].find((s) => bySev(s) > 0)
  const summary = findings.length
    ? `${host} — ${findings.length} finding(s); worst: ${worst}. ${open.length} open port(s).`
    : `${host} — no issues found across ${ports.length} ports${dns ? ' + DNS' : ''}. ${open.length} open port(s).`

  const framedFields = tlsInfos.length + httpInfos.filter((h) => h.server).length
  const signals = [dns != null, open.length > 0, tlsInfos.length > 0].filter(Boolean).length
  const confidence: Confidence = signals >= 2 ? 'strong' : signals === 1 ? 'moderate' : 'weak'

  return {
    target: { input, host, kind: t.kind, scope: t.scope },
    authorized: true,
    summary, dns, ports: portResults, tls: tlsInfos, http: httpInfos, findings,
    confidence, sanitization: { framedFields }, notes: [],
  }
}
