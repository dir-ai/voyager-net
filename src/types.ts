// voyager-net — shapes for read-only, AUTHORIZED introspection of a single host
// or domain you own. Finds the falle (DNS/ports/TLS/HTTP hygiene) and DESCRIBES a
// fix; it never applies one, never exploits, never scans ranges.

export type Confidence = 'strong' | 'moderate' | 'weak'
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface NetFinding {
  severity: Severity
  kind: string
  /** What is wrong, in one line. */
  detail: string
  /** Where (host:port / record), for the agent to act on. */
  at?: string
  /** A DESCRIBED remediation — never applied by voyager-net. */
  suggestedFix?: string
  confidence: Confidence
}

/** Codex #1: a real port state, not just open/closed — the agent must tell a
 *  firewalled/filtered port apart from a refused one apart from an unreachable host. */
export type PortState = 'open' | 'closed' | 'filtered' | 'unreachable'

export interface PortResult {
  port: number
  state: PortState
  /** Convenience: state === 'open'. */
  open: boolean
  /** Guessed from the port number (weak). */
  service?: string
  /** PASSIVELY identified product from the volunteered banner — FRAMED. */
  product?: string
  /** Version parsed from the banner, when the service volunteers it. */
  version?: string
  /** The raw volunteered banner — FRAMED (untrusted), bounded. */
  banner?: string
}

export interface TlsInfo {
  port: number
  protocol: string | null
  cipher: string | null
  issuer: string | null
  subject: string | null
  altNames: string[]
  validFrom: string | null
  validTo: string | null
  daysToExpiry: number | null
  selfSigned: boolean | null
  /** Which TLS versions the endpoint ACCEPTS (probed, not just the negotiated one). */
  supportedProtocols: string[]
  /** Does the chain validate against the system trust store for this hostname? */
  trusted: boolean | null
  keyBits: number | null
}

export interface DnsInfo {
  a: string[]
  aaaa: string[]
  mx: string[]
  txt: string[]
  caa: string[]
  hasSpf: boolean
  hasDmarc: boolean
  hasCaa: boolean
  /** Raw SPF / DMARC records (for content grading: +all, p=none). */
  spf: string | null
  dmarc: string | null
}

export interface HttpSurface {
  port: number
  url: string
  status: number | null
  /** Server header — FRAMED. */
  server: string | null
  /** Security headers present/absent. */
  securityHeaders: Record<string, boolean>
  /** Raw values of key security headers (for quality grading). FRAMED. */
  headerValues: { hsts: string | null; csp: string | null }
  /** EACH Set-Cookie evaluated individually (a blob join would mask a bad one). */
  cookies: Array<{ name: string; secure: boolean; httpOnly: boolean; sameSite: boolean }>
  /** Access-Control-Allow-Origin value — FRAMED (target-controlled). */
  cors: string | null
  /** Access-Control-Allow-Credentials: true (dangerous combined with a set ACAO). */
  corsCredentials: boolean
  /** An http:// root that 301/302s to https://. */
  redirectsToHttps: boolean
}

export interface NetBrief {
  target: { input: string; host: string | null; kind: 'ip' | 'domain' | 'invalid'; scope: 'loopback' | 'private' | 'public' | 'unknown' }
  /** The single IP the domain resolved to and that ALL probes were pinned to
   *  (anti DNS-rebinding: we resolve once and never re-resolve mid-scan). */
  resolvedIp: string | null
  authorized: boolean
  summary: string
  dns: DnsInfo | null
  ports: PortResult[]
  tls: TlsInfo[]
  http: HttpSurface[]
  findings: NetFinding[]
  confidence: Confidence
  /** What to probe next to deepen understanding — toward the universal contract. */
  suggestedNextProbes: string[]
  sanitization: { framedFields: number }
  notes: string[]
  /** Set when the scan could not run (not authorized, invalid/blocked target,
   *  tool error). Distinguishes "couldn't check" from "found nothing wrong". */
  error?: string
}

export interface ScanOptions {
  /** REQUIRED to actually probe: you assert you own / are authorized to test the
   *  target. Without it the scan refuses (fail-closed). */
  authorized?: boolean
  /** Ports to probe (default: a small common set). Single ports only. */
  ports?: number[]
  /** Per-connection timeout ms. */
  timeoutMs?: number
  onLog?: (line: string) => void
}
