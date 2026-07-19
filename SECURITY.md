# Security

voyager-net points network probes at a target, so restraint is the whole design.
It is an auditing tool for **your own** infrastructure.

## Authorized-only, fail-closed

A scan does nothing until you assert authorization (`--authorized` / `authorized:
true`). This is a deliberate friction: you are stating that you own, or have
explicit permission to test, the target. Absent it, the tool returns an error and
makes no network connection.

## Cannot become a mass scanner

`parseTarget` accepts exactly **one** host or domain. CIDR blocks, IP ranges,
comma lists, wildcards, and URLs are rejected. There is no range mode and no
recursive discovery — one target per invocation, by construction.

## Blocked targets

Cloud instance-metadata endpoints (`169.254.169.254`, `metadata.google.internal`,
`100.100.100.200`, …) are hard-blocked regardless of authorization — probing them
is an SSRF/credential-theft vector, never a legitimate ops check.

## Read-only and non-intrusive

- Ports are checked with a plain TCP `connect()` — no raw sockets, no SYN scans,
  no payloads, no exploitation.
- Bounded concurrency and per-connection timeouts; a small common-service port set
  by default, never a 65k sweep.
- TLS/HTTP inspection reads the certificate and response headers of the root only;
  no path crawling, no request flooding.
- The tool **never applies a remediation** — findings describe a fix; a human (or
  a separate, consent-gated organ) decides and applies it.

## Untrusted target output

Server banners and certificate fields are attacker-controlled; each is
injection-stripped (via `@dir-ai/voyager`) before it enters a finding, so a
hostile host cannot smuggle instructions into your model.

## Reporting

Please report vulnerabilities via a private GitHub security advisory rather than a
public issue.
