#!/usr/bin/env node
/**
 * voyager-net CLI — safe, read-only, AUTHORIZED introspection of one host/domain.
 */
import { scan } from './scan.js'
import { VERSION } from './version.js'
import type { NetBrief, ScanOptions } from './types.js'

function parseArgs(argv: string[]): { flags: Record<string, string | boolean>; positionals: string[] } {
  const boolean = new Set(['json', 'authorized'])
  const flags: Record<string, string | boolean> = {}
  const positionals: string[] = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a.startsWith('--')) {
      const key = a.slice(2)
      const next = argv[i + 1]
      if (!boolean.has(key) && next !== undefined && !next.startsWith('--')) { flags[key] = next; i++ }
      else flags[key] = true
    } else positionals.push(a)
  }
  return { flags, positionals }
}

const HELP = `voyager-net v${VERSION} — Voyager's network organ: a safe, read-only host audit

USAGE
  voyager-net scan <host|domain> --authorized [--ports 22,80,443] [--timeout ms] [--json]
        Introspect ONE host or domain you OWN: DNS, open ports, TLS certs, HTTP
        security headers → findings + DESCRIBED fixes. READ-ONLY: it never applies
        a fix, exploits, floods, or scans ranges/CIDR.
        --authorized is REQUIRED: you assert you own / may test the target.
        Exit: 0 clean · 1 high/critical finding(s) · 2 tool error / not authorized.

  voyager-net mcp                Start the stdio MCP server (tool: scan_host).
  voyager-net help | --version

Scanning infrastructure you do not own or have permission to test may be illegal.`

const SEV: Record<string, string> = { critical: '⛔', high: '⛔', medium: '⚠', low: '·', info: 'ℹ' }

function render(b: NetBrief): void {
  if (b.error) { console.error(`✗ ${b.error}`); return }
  console.log(`\n${b.summary}`)
  console.log(`  scope: ${b.target.scope} · confidence: ${b.confidence} · ${b.sanitization.framedFields} framed field(s)`)

  const open = b.ports.filter((p) => p.open)
  if (open.length) console.log(`\nopen ports: ${open.map((p) => `${p.port}${p.service ? `/${p.service}` : ''}`).join(', ')}`)
  for (const c of b.tls) console.log(`  tls :${c.port} ${c.protocol ?? '?'} · issuer ${c.issuer ?? '?'} · expires ${c.validTo ?? '?'}${c.daysToExpiry != null ? ` (${c.daysToExpiry}d)` : ''}`)
  for (const h of b.http) {
    const missing = Object.entries(h.securityHeaders).filter(([, v]) => !v).map(([k]) => k)
    console.log(`  http :${h.port} ${h.status ?? '?'}${h.server ? ` · ${h.server}` : ''}${missing.length ? ` · missing: ${missing.join(', ')}` : ''}`)
  }
  if (b.dns) console.log(`\ndns: A ${b.dns.a.length}, MX ${b.dns.mx.length}, SPF ${b.dns.hasSpf ? '✓' : '✗'}, DMARC ${b.dns.hasDmarc ? '✓' : '✗'}, CAA ${b.dns.hasCaa ? '✓' : '✗'}`)

  if (b.findings.length) {
    console.log(`\nfindings:`)
    for (const f of b.findings) {
      console.log(`  ${SEV[f.severity] ?? '·'} [${f.severity}] ${f.kind}: ${f.detail}${f.at ? ` (${f.at})` : ''}`)
      if (f.suggestedFix) console.log(`      fix: ${f.suggestedFix}`)
    }
  } else {
    console.log(`\n✓ no findings`)
  }
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2)
  const { flags, positionals } = parseArgs(rest)
  const json = flags.json === true

  switch (cmd) {
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      console.log(HELP)
      return 0
    case '--version':
    case 'version':
      console.log(VERSION)
      return 0

    case 'scan': {
      const target = positionals[0]
      if (!target) { console.error('scan needs a host or domain.'); return 2 }
      const opts: ScanOptions = {
        authorized: flags.authorized === true,
        ports: typeof flags.ports === 'string' ? flags.ports.split(',').map((p) => Number(p.trim())).filter((n) => Number.isInteger(n)) : undefined,
        timeoutMs: typeof flags.timeout === 'string' ? Number(flags.timeout) || undefined : undefined,
        onLog: (l) => { if (!json) console.error(`  · ${l}`) },
      }
      const b = await scan(target, opts)
      if (json) console.log(JSON.stringify(b, null, 2))
      else render(b)
      if (b.error) return 2
      return b.findings.some((f) => f.severity === 'high' || f.severity === 'critical') ? 1 : 0
    }

    case 'mcp': {
      const { startMcpServer } = await import('./mcp.js')
      await startMcpServer()
      return new Promise<number>(() => {})
    }

    default:
      console.error(`Unknown command: ${cmd}\n`)
      console.log(HELP)
      return 2
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(err instanceof Error ? (err.stack ?? err.message) : String(err))
    process.exit(2)
  })
