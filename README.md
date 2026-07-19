# voyager-net

**Voyager's network organ — a safe, read-only, *authorized* audit of one host or
domain you own, so an AI agent can find the falle in your infra and describe the
fix.**

Voyager penetrates the **web** (`@dir-ai/voyager`), the **repo**
(`@dir-ai/voyager-repo`), and — here — **networks**. This is the *sense*: it finds
problems. Applying fixes ("the hands") is a separate, consent-gated organ, by
design — an AI must never mutate live infrastructure on its own.

```bash
voyager-net scan yourhost.example.com --authorized
voyager-net scan 10.0.5.20 --authorized --ports 22,80,443,5432
```

## What it checks (read-only)

- **DNS** — A/AAAA/MX/TXT/CAA + email/CA hygiene (SPF, DMARC, CAA present?)
- **Ports** — a bounded common-service probe by plain TCP `connect()` (no SYN
  tricks, no payloads, no range/CIDR sweeps)
- **TLS** — certificate expiry, issuer, self-signed, deprecated protocol (TLS 1.0/1.1)
- **HTTP hygiene** — status, Server banner (framed), missing security headers
  (HSTS, CSP, X-Frame-Options, …)

Each finding carries a **severity**, **confidence**, and a **described fix** — e.g.
"certificate expires in 6d → renew and automate ACME", "mysql reachable publicly →
restrict to a private network", "no DMARC → publish `v=DMARC1; p=quarantine`".

## Safety — non-negotiable

- **Authorized-only, fail-closed.** Without `--authorized` (CLI) / `authorized:true`
  (MCP) it refuses. You assert you own / may test the target.
- **One host or domain only.** CIDR ranges, IP ranges, lists, wildcards, and URLs
  are rejected — it can never become a mass scanner.
- **Cloud metadata endpoints are hard-blocked** (169.254.169.254 etc.).
- **Read-only.** It never applies a fix, exploits, floods, or mutates anything.
  Bounded concurrency and timeouts; a plain TCP connect, not a scanner's SYN sweep.
- **Untrusted output framed.** Banners and certificate fields from the target are
  injection-stripped before your model sees them.
- **Exit codes:** `0` clean · `1` high/critical finding(s) · `2` tool error / not authorized.

> Scanning infrastructure you do not own or have explicit permission to test may
> be illegal in your jurisdiction. This tool is for auditing **your own** systems.

## MCP

```bash
voyager-net mcp
```

Tool: `scan_host` — same audit, fail-closed (`authorized` defaults off).

## Library

```ts
import { scan } from '@dir-ai/voyager-net'
const brief = await scan('yourhost.example.com', { authorized: true })
const urgent = brief.findings.filter((f) => f.severity === 'high' || f.severity === 'critical')
```

## Roadmap

Wrap Prowler/Steampipe (cloud config), Trivy (CVE), Hubble (flow) under the same
trust contract; attack-path correlation; drift (IaC declared ↔ actual). Then —
separately and consent-gated — the remediation "hands".

## License

MIT
