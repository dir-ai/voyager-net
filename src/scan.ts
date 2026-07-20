import { lookup, resolve4, resolve6 } from 'node:dns/promises'
import { parseTarget, blockedIpReason } from './authorize.js'
import { scanDns } from './dns.js'
import { scanPorts, DEFAULT_PORTS } from './ports.js'
import { scanUnauth } from './unauth.js'
import { inspectSsh } from './ssh.js'
import { fingerprintDb } from './dbfingerprint.js'
import { inspectStartTls } from './starttls.js'
import { inspectTls } from './tls.js'
import { inspectHttp } from './http.js'
import type { Confidence, NetBrief, NetFinding, ScanOptions } from './types.js'

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

  // ── Resolve and pin (anti-rebinding). DUAL-STACK: a domain can have A *and* AAAA
  // records; a service exposed only over IPv6 is invisible if you pin a single v4
  // (Kimi #6). Resolve BOTH families, vet each, scan the primary fully and the extra
  // addresses in a lighter pass so a v6-only service is still caught. ────────────
  let resolvedIp: string | null = t.kind === 'ip' ? host : null
  let extraAddrs: string[] = []
  if (t.kind === 'domain') {
    let all: string[] = []
    try {
      const [v4, v6] = await Promise.all([resolve4(host).catch(() => [] as string[]), resolve6(host).catch(() => [] as string[])])
      all = [...v4, ...v6]
      if (!all.length) all = [(await lookup(host)).address]
    } catch {
      return { ...base(), error: `could not resolve ${host}` }
    }
    const vetted = all.filter((ip) => !blockedIpReason(ip)).slice(0, 4)
    if (!vetted.length) return { ...base(), resolvedIp: all[0] ?? null, error: `${host} ${blockedIpReason(all[0] ?? '') ?? 'resolves only to blocked addresses'}` }
    resolvedIp = vetted[0]
    extraAddrs = vetted.slice(1)
  }
  const pin = resolvedIp ?? host

  const dns = t.kind === 'domain' ? await (log('resolving DNS…'), scanDns(host, timeoutMs)) : null

  log(`probing ${ports.length} ports…`)
  const portResults = await scanPorts(pin, ports, timeoutMs)
  const open = portResults.filter((p) => p.state === 'open')

  log('inspecting TLS + HTTP…')
  // Inspect by PROTOCOL, not by hardcoded port number: an HTTP admin panel on
  // :31811 or a DB speaking TLS on :31813 must not be skipped just because the
  // port isn't in a fixed set. Try TLS on EVERY open port; where it handshakes
  // it's TLS (→ probe HTTP-over-TLS), else try plain HTTP. All pinned to the IP.
  const tlsInfos = (await Promise.all(open.map((p) => inspectTls(pin, p.port, host, timeoutMs + 3000)))).filter(Boolean) as NonNullable<Awaited<ReturnType<typeof inspectTls>>>[]
  const tlsPorts = new Set(tlsInfos.map((t) => t.port))
  const httpInfos = (await Promise.all(open.map((p) => inspectHttp(pin, host, p.port, tlsPorts.has(p.port), timeoutMs + 3000)))).filter(Boolean) as NonNullable<Awaited<ReturnType<typeof inspectHttp>>>[]

  // ── Unauthenticated-service detection (N1): does an open datastore/admin port
  // answer a benign protocol hello with NO auth? (Redis PING, Elastic GET, …) ────
  log('probing exposed services for missing authentication…')
  const inspected = new Set<number>([...tlsPorts, ...httpInfos.map((h) => h.port)])
  const unauthFindings = await scanUnauth(pin, host, open, timeoutMs, inspected)

  // SSH weak-algorithm audit on any port speaking SSH (port 22 or fingerprinted).
  const sshPorts = open.filter((p) => p.port === 22 || /ssh/i.test(`${p.product ?? ''} ${p.service ?? ''}`))
  const sshFindings = (await Promise.all(sshPorts.map((p) => inspectSsh(pin, host, p.port, timeoutMs + 2000)))).flat()
  const dbFindings = await fingerprintDb(pin, host, open, inspected, timeoutMs)
  const startTlsPorts = open.filter((p) => [25, 587, 143, 110].includes(p.port))
  const startTlsFindings = (await Promise.all(startTlsPorts.map((p) => inspectStartTls(pin, host, p.port, timeoutMs + 2000)))).flat()

  // Dual-stack: scan every ADDITIONAL resolved address (e.g. the IPv6) for open
  // ports + unauth/db/ssh, so a service exposed only there isn't missed.
  const extraFindings = (await Promise.all(extraAddrs.map((addr) => scanExtraAddress(addr, host, ports, timeoutMs)))).flat()

  // ── Findings ────────────────────────────────────────────────────────────────
  const findings: NetFinding[] = [...unauthFindings, ...sshFindings, ...dbFindings, ...startTlsFindings, ...extraFindings]
  const notes: string[] = []
  // Honesty: an open port with NO banner and no TLS/HTTP answer is genuinely
  // unknown (not "clean"). A fingerprinted service (ssh/redis/…) isn't "dark".
  const inspectedPorts = new Set<number>([...tlsPorts, ...httpInfos.map((h) => h.port)])
  const dark = open.filter((p) => !inspectedPorts.has(p.port) && !p.product)
  if (dark.length) notes.push(`${dark.length} open port(s) volunteered no banner and answered neither TLS nor HTTP — service UNKNOWN, not clean (ports: ${dark.map((p) => p.port).slice(0, 12).join(', ')})`)

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
    // Emit whenever the chain fails validation — self-signed is just one reason;
    // untrusted CA / incomplete chain / name mismatch also matter and were silent.
    if (c.trusted === false) findings.push({ severity: 'medium', kind: 'tls-untrusted', detail: c.selfSigned ? 'certificate not trusted by the system store (self-signed)' : 'certificate chain does not validate against the system trust store (untrusted CA, incomplete chain, or name mismatch)', at: `${host}:${c.port}`, suggestedFix: 'use a CA-issued certificate with a complete chain matching the hostname', confidence: 'moderate' })
    // Only RSA has the <2048 rule; EC/EdDSA keys have small bit counts BY DESIGN
    // (nulled in tls.ts for named curves; the ≥512 floor also excludes Ed25519 ≈253).
    if (c.keyBits != null && c.keyBits >= 512 && c.keyBits < 2048) findings.push({ severity: 'medium', kind: 'weak-key', detail: `${c.keyBits}-bit RSA key (below 2048)`, at: `${host}:${c.port}`, suggestedFix: 'reissue with a ≥2048-bit RSA or an EC key', confidence: 'strong' })
  }

  for (const h of httpInfos) {
    const isHttps = h.url.startsWith('https')
    // HSTS — grade quality, not just presence.
    if (isHttps && !h.securityHeaders['strict-transport-security']) findings.push({ severity: 'medium', kind: 'missing-hsts', detail: 'HTTPS without HSTS', at: h.url, suggestedFix: 'add `Strict-Transport-Security: max-age=63072000; includeSubDomains`', confidence: 'strong' })
    else if (isHttps && h.headerValues.hsts) {
      const maxAge = Number(/max-age\s*=\s*(\d+)/i.exec(h.headerValues.hsts)?.[1] ?? 0)
      if (maxAge < 15_552_000 || !/includesubdomains/i.test(h.headerValues.hsts)) findings.push({ severity: 'low', kind: 'weak-hsts', detail: `HSTS is weak (${maxAge < 15_552_000 ? 'max-age below 180d' : 'no includeSubDomains'})`, at: h.url, suggestedFix: 'use max-age ≥ 63072000 with includeSubDomains (consider preload)', confidence: 'strong' })
    }
    // CORS — wildcard, or (the dangerous case) a reflected/specific origin WITH credentials.
    if (h.cors === '*') findings.push({ severity: 'medium', kind: 'cors-wildcard', detail: 'Access-Control-Allow-Origin: * (any origin)', at: h.url, suggestedFix: 'restrict CORS to the specific trusted origin(s)', confidence: 'strong' })
    else if (h.cors && h.corsCredentials) findings.push({ severity: 'high', kind: 'cors-credentials', detail: `CORS allows credentials for origin "${h.cors}" — verify it cannot be reflected/attacker-controlled`, at: h.url, suggestedFix: 'never combine Allow-Credentials:true with a reflected or overly broad origin', confidence: 'moderate' })
    // Cookies — evaluate EACH individually (a good cookie no longer masks a bad one).
    for (const c of h.cookies) {
      if (!c.secure || !c.httpOnly) findings.push({ severity: 'low', kind: 'weak-cookie', detail: `cookie "${c.name}" missing ${[!c.secure && 'Secure', !c.httpOnly && 'HttpOnly'].filter(Boolean).join(' + ')}`, at: h.url, suggestedFix: 'set Secure + HttpOnly (and SameSite) on session cookies', confidence: 'strong' })
    }
    // CSP — grade quality.
    if (!h.securityHeaders['content-security-policy']) findings.push({ severity: 'low', kind: 'missing-csp', detail: 'no Content-Security-Policy', at: h.url, suggestedFix: 'add a Content-Security-Policy', confidence: 'moderate' })
    else if (h.headerValues.csp) {
      const c = h.headerValues.csp.toLowerCase()
      const w: string[] = []
      if (c.includes("'unsafe-inline'")) w.push('unsafe-inline')
      if (c.includes("'unsafe-eval'")) w.push('unsafe-eval')
      if (/(?:default|script)-src[^;]*\*(?![.\w-])/.test(c)) w.push('wildcard-src')
      if (w.length) findings.push({ severity: 'low', kind: 'weak-csp', detail: `CSP present but weak: ${w.join(', ')}`, at: h.url, suggestedFix: "remove unsafe-inline/unsafe-eval and wildcard sources", confidence: 'moderate' })
    }
    // Clickjacking + version leak.
    if (isHttps && !h.securityHeaders['x-frame-options'] && !/frame-ancestors/i.test(h.headerValues.csp ?? '')) findings.push({ severity: 'low', kind: 'missing-frame-protection', detail: 'no clickjacking protection (X-Frame-Options / CSP frame-ancestors)', at: h.url, suggestedFix: "add X-Frame-Options: DENY or CSP frame-ancestors 'none'", confidence: 'moderate' })
    if (h.server && /\d/.test(h.server)) findings.push({ severity: 'low', kind: 'version-leak', detail: `server version disclosed in header: ${h.server}`, at: h.url, suggestedFix: 'remove version details from the Server header', confidence: 'moderate' })
    if (h.app) findings.push({ severity: 'medium', kind: 'app-exposed', detail: `web application identified: ${h.app} — reachable at ${h.url}`, at: h.url, suggestedFix: `confirm ${h.app} is meant to be exposed here; if it is an admin/ops console, put it behind auth/VPN and check ${h.app} against your CVE feed`, confidence: 'moderate' })
  }
  for (const h of httpInfos) if (h.url.startsWith('http://') && !h.redirectsToHttps) findings.push({ severity: 'low', kind: 'no-https-redirect', detail: 'plain HTTP does not redirect to HTTPS', at: h.url, suggestedFix: 'redirect all HTTP to HTTPS (301)', confidence: 'strong' })

  if (dns) {
    if (dns.mx.length && !dns.hasSpf) findings.push({ severity: 'medium', kind: 'missing-spf', detail: 'sends mail (MX) but no SPF record', at: host, suggestedFix: 'publish an SPF TXT record', confidence: 'strong' })
    else if (dns.spf && /\+all\b/i.test(dns.spf)) findings.push({ severity: 'high', kind: 'spf-permissive', detail: 'SPF contains +all — anyone may send as this domain', at: host, suggestedFix: 'end SPF with -all (fail) or ~all (softfail), never +all', confidence: 'strong' })
    if (dns.mx.length && !dns.hasDmarc) findings.push({ severity: 'medium', kind: 'missing-dmarc', detail: 'no DMARC record', at: host, suggestedFix: 'publish `v=DMARC1; p=quarantine; …`', confidence: 'strong' })
    else if (dns.dmarc && /p=none/i.test(dns.dmarc)) findings.push({ severity: 'low', kind: 'dmarc-none', detail: 'DMARC policy is p=none (monitor only — no enforcement)', at: host, suggestedFix: 'move DMARC to p=quarantine then p=reject once aligned', confidence: 'strong' })
    if (!dns.hasCaa) findings.push({ severity: 'low', kind: 'missing-caa', detail: 'no CAA record — any CA may issue certs', at: host, suggestedFix: 'add a CAA record pinning your CA(s)', confidence: 'moderate' })
  }

  // ── Summary + confidence + next probes ──────────────────────────────────────
  const worst = ['critical', 'high', 'medium', 'low', 'info'].find((s) => findings.some((f) => f.severity === s))
  const ipTag = resolvedIp && resolvedIp !== host ? ` (${resolvedIp})` : ''
  const partial = notes.length > 0
  const summary = findings.length
    ? `${host}${ipTag} — ${findings.length} finding(s); worst: ${worst}. ${open.length} open port(s).${partial ? ' Some open ports could not be inspected (posture PARTIAL).' : ''}`
    : partial
      ? `${host}${ipTag} — ${open.length} open port(s) but some could not be inspected; posture PARTIAL/UNKNOWN, not necessarily clean.`
      : open.length === 0 && !dns
        ? `${host}${ipTag} — nothing observable (no open ports, no DNS records).`
        : `${host}${ipTag} — no issues across ${ports.length} ports${dns ? ' + DNS' : ''}. ${open.length} open port(s).`

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
    confidence, suggestedNextProbes, sanitization: { framedFields }, notes,
  }
}

/** Lighter scan of an ADDITIONAL resolved address (dual-stack) — open ports +
 *  unauth/db/ssh + exposed-service, tagged with the address so a v6-only service is
 *  attributable. Read-only, pinned to the vetted address. */
async function scanExtraAddress(addr: string, host: string, ports: number[], timeoutMs: number): Promise<NetFinding[]> {
  const label = `${host}[${addr}]`
  const open = (await scanPorts(addr, ports, timeoutMs)).filter((p) => p.state === 'open')
  if (!open.length) return []
  const [unauth, db] = await Promise.all([scanUnauth(addr, label, open, timeoutMs, new Set()), fingerprintDb(addr, label, open, new Set(), timeoutMs)])
  const ssh = (await Promise.all(open.filter((p) => p.port === 22).map((p) => inspectSsh(addr, label, p.port, timeoutMs + 2000)))).flat()
  const exposed: NetFinding[] = []
  for (const p of open) if (SENSITIVE[p.port]) exposed.push({ severity: 'high', kind: 'exposed-service', detail: `${SENSITIVE[p.port]} (port ${p.port}) reachable on ${addr.includes(':') ? 'IPv6' : 'IPv4'} ${addr}`, at: `${label}:${p.port}`, suggestedFix: `restrict ${SENSITIVE[p.port]} to a private network / VPN`, confidence: 'strong' })
  return [...unauth, ...db, ...ssh, ...exposed]
}
