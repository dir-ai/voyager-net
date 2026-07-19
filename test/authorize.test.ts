import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseTarget, scan } from '../dist/index.js'

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
