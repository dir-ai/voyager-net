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

export interface PortResult {
  port: number
  open: boolean
  service?: string
  /** Server/product banner if volunteered — FRAMED (untrusted). */
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
}

export interface HttpSurface {
  port: number
  url: string
  status: number | null
  /** Server header — FRAMED. */
  server: string | null
  /** Security headers present/absent. */
  securityHeaders: Record<string, boolean>
}

export interface NetBrief {
  target: { input: string; host: string | null; kind: 'ip' | 'domain' | 'invalid'; scope: 'loopback' | 'private' | 'public' | 'unknown' }
  authorized: boolean
  summary: string
  dns: DnsInfo | null
  ports: PortResult[]
  tls: TlsInfo[]
  http: HttpSurface[]
  findings: NetFinding[]
  confidence: Confidence
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
