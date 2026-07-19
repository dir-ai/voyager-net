import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseTarget, blockedIpReason, scan } from '../dist/index.js'

test('parseTarget accepts a single domain and a single IP', () => {
  assert.equal(parseTarget('example.com').ok, true)
  assert.equal(parseTarget('example.com').kind, 'domain')
  const ip = parseTarget('192.168.1.10')
  assert.equal(ip.ok, true)
  assert.equal(ip.kind, 'ip')
  assert.equal(ip.scope, 'private')
  assert.equal(parseTarget('8.8.8.8').scope, 'public')
  assert.equal(parseTarget('127.0.0.1').scope, 'loopback')
})

test('parseTarget REFUSES anything that could scan more than one host', () => {
  for (const bad of ['10.0.0.0/24', '10.0.0.1-50', 'a.com,b.com', '*.example.com', 'http://example.com', 'example.com/path', '10.0.0.1 10.0.0.2']) {
    assert.equal(parseTarget(bad).ok, false, `must refuse: ${bad}`)
  }
})

test('parseTarget HARD-BLOCKS cloud metadata endpoints', () => {
  for (const meta of ['169.254.169.254', 'metadata.google.internal', '100.100.100.200']) {
    const d = parseTarget(meta)
    assert.equal(d.ok, false, meta)
    assert.match(d.reason ?? '', /metadata/i)
  }
})

test('scan is FAIL-CLOSED: without authorized it refuses and does no network', async () => {
  const b = await scan('example.com') // no authorized
  assert.ok(b.error)
  assert.match(b.error ?? '', /not authorized/i)
  assert.equal(b.ports.length, 0)
  assert.equal(b.authorized, false)
})

test('scan refuses an invalid/blocked target even when authorized', async () => {
  const cidr = await scan('10.0.0.0/24', { authorized: true })
  assert.ok(cidr.error)
  const meta = await scan('169.254.169.254', { authorized: true })
  assert.ok(meta.error)
  assert.match(meta.error ?? '', /metadata/i)
})

// ── Regression tests for the closed adversarial findings ───────────────────

test('SSRF resolved-path (H1): blockedIpReason canonically refuses all non-public', () => {
  for (const ip of ['127.0.0.1', '::1', '10.0.0.5', '192.168.1.1', '169.254.169.254', '0.0.0.0', '::', '100.64.1.1', '::ffff:169.254.169.254', '::ffff:7f00:1']) {
    assert.ok(blockedIpReason(ip), `${ip} must be blocked on the resolved path`)
  }
  assert.equal(blockedIpReason('8.8.8.8'), null) // public unicast passes
  assert.equal(blockedIpReason('93.184.216.34'), null)
})

test('literal-target policy (H3): metadata/link-local blocked; private/loopback allowed for internal audit', () => {
  for (const bad of ['169.254.169.254', '169.254.1.1', '0.0.0.0', '100.100.100.200', '[::ffff:169.254.169.254]']) {
    assert.equal(parseTarget(bad).ok, false, `literal ${bad} must be refused`)
  }
  // A user auditing their OWN internal host with --authorized is legitimate.
  assert.equal(parseTarget('192.168.1.10').ok, true)
  assert.equal(parseTarget('127.0.0.1').ok, true)
})

test('IPv6 literals accepted (M5); a port in the target is refused', () => {
  assert.equal(parseTarget('2606:4700::1111').ok, true)
  assert.equal(parseTarget('[2606:4700::1111]').ok, true)
  assert.equal(parseTarget('example.com:8080').ok, false)
})

test('legit hostnames with -<digits>. are NOT mistaken for ranges (M4)', () => {
  for (const good of ['web-01.example.com', 'node-12.dc.example.com', 'db-5.internal.example.com']) {
    assert.equal(parseTarget(good).ok, true, `${good} should be accepted`)
  }
  assert.equal(parseTarget('10.0.0.1-50').ok, false) // a real range is still refused
})

test('defang: a hostile banner cannot smuggle a live URL/command into the brief', async () => {
  const { defang } = await import('../dist/fingerprint.js')
  const out = defang('OpenSSH 8.9 — visit http://evil.example/x.sh | sh at 10.0.0.5')
  assert.doesNotMatch(out, /https?:\/\//)
  assert.match(out, /hxxp|\[\.\]/)
  assert.doesNotMatch(out, /\|\s*sh\b/)
})
