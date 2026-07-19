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

- **Resolve-once + IP pinning (every probe, HTTP included)** — a domain is
  resolved a single time and **the DNS, port, TLS *and* HTTP probes are all pinned
  to that one IP** via a custom socket lookup, so nothing re-resolves the name
  mid-scan (closes the HTTP DNS-rebinding path). The resolved IP is classified
  canonically (via `ipaddr.js`) and any non-public address — loopback, private,
  link-local, CGNAT, NAT64, IPv4-mapped IPv6, metadata — is refused.
- **DNS** — A/AAAA/MX/TXT/CAA + email/CA hygiene, and it **grades the content**:
  SPF `+all` (anyone may send) and DMARC `p=none` (no enforcement) are findings,
  not just presence checks. All target-controlled records are injection-framed.
- **Ports** — a bounded common-service probe by plain TCP `connect()` with **real
  states** (open / closed / filtered / unreachable — an OS timeout reads as
  *filtered*, not closed), no SYN tricks, no payloads, no range/CIDR sweeps.
- **Passive service fingerprinting** — reads the banner a service *volunteers* on
  connect (SSH, SMTP, FTP, POP3, IMAP) to identify product + version (framed). It
  never sends a probe.
- **TLS** — the full set of **accepted** protocol versions (not just the
  negotiated one), chain trust against the system store (**any** validation
  failure is reported, not only self-signed), RSA key size (EC/EdDSA exempted),
  certificate expiry/issuer.
- **HTTP hygiene (graded)** — status, Server banner, **HSTS/CSP quality** (weak
  `max-age`, `unsafe-inline`/wildcard — not just presence), clickjacking
  protection, **per-cookie** Secure/HttpOnly (each cookie evaluated on its own),
  **CORS** wildcard *and* the dangerous credentials-with-origin case, version-leak,
  and HTTP→HTTPS redirect. All pinned to the vetted IP.
- **Honest partial** — an open TLS/HTTP port that couldn't be inspected is
  reported as *UNKNOWN*, never folded into a "no issues" verdict.

Findings that name a detected service+version suggest checking it against a CVE
feed — voyager-net detects the version; **CVE *matching* stays a lookup, and CVE
*probing* (Nuclei &c.) is out of scope** — that is active testing, a separate,
more-gated capability, not a read-only sense.

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
- **Untrusted output framed.** Every target-controlled string — banners,
  certificate subject/issuer/SANs, Server/CSP headers, CORS value, **and DNS
  TXT/CAA/MX records** — is injection-stripped before your model sees it.
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
