import { test } from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import tls from 'node:tls'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { scan, scanUnauth } from '../dist/index.js'

const bind = (srv: net.Server): Promise<number> => new Promise((r) => srv.listen(0, '127.0.0.1', () => r((srv.address() as net.AddressInfo).port)))

test('scanUnauth: rsync daemon (@RSYNCD banner) and Kafka (ApiVersions echo) are flagged', async () => {
  const rsync = net.createServer((s) => { s.on('error', () => {}); s.write('@RSYNCD: 31.0\n') }); rsync.on('error', () => {})
  const kafka = net.createServer((s) => { s.on('error', () => {}); s.on('data', () => { const b = Buffer.alloc(14); b.writeUInt32BE(10, 0); b.writeUInt32BE(1, 4); s.write(b) }) }); kafka.on('error', () => {})
  const rp = await bind(rsync); const kp = await bind(kafka)
  try {
    assert.ok((await scanUnauth('127.0.0.1', 'h', [{ port: rp, state: 'open', open: true }], 2000, new Set(), new Set())).some((x) => /rsync/i.test(x.detail)))
    assert.ok((await scanUnauth('127.0.0.1', 'h', [{ port: kp, state: 'open', open: true }], 2000, new Set(), new Set())).some((x) => /Kafka/i.test(x.detail)))
  } finally { rsync.close(); kafka.close() }
})

test('scanUnauth: Solr admin (lucene/solr-spec-version) on an HTTP port is flagged', async () => {
  const solr = net.createServer((s) => { s.on('error', () => {}); s.on('data', () => s.write('HTTP/1.0 200 OK\r\n\r\n{"lucene":{"solr-spec-version":"9.0"}}')) }); solr.on('error', () => {})
  const sp = await bind(solr)
  try { assert.ok((await scanUnauth('127.0.0.1', 'h', [{ port: sp, state: 'open', open: true }], 2000, new Set(), new Set([sp]))).some((x) => /Solr/i.test(x.detail))) } finally { solr.close() }
})

test('cipher audit: legacy-cbc fires on a REAL ECDHE-CBC TLS1.2 handshake (not synthetic)', async () => {
  let key: Buffer, cert: Buffer
  try {
    const dir = mkdtempSync(join(tmpdir(), 'vk-'))
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', join(dir, 'k'), '-out', join(dir, 'c'), '-days', '1', '-nodes', '-subj', '/CN=localhost'], { stdio: 'ignore' })
    key = readFileSync(join(dir, 'k')); cert = readFileSync(join(dir, 'c'))
  } catch { return } // openssl unavailable → soft-skip
  const srv = tls.createServer({ key, cert, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2', ciphers: 'ECDHE-RSA-AES256-SHA384' }, (s) => s.end()); srv.on('error', () => {})
  const tp = await new Promise<number>((r) => srv.listen(0, '127.0.0.1', () => r((srv.address() as net.AddressInfo).port)))
  try {
    const b = await scan('127.0.0.1', { authorized: true, ports: [tp], timeoutMs: 3000 })
    assert.ok(b.findings.some((f) => f.kind === 'legacy-cbc'), 'legacy-cbc detected on a genuine CBC handshake')
  } finally { srv.close() }
})

// Kimi Canto VI #21 (the reverse gate): a server that accepts ONLY TLS 1.0 must NOT
// be invisible. The old base handshake used modern defaults and returned null when
// they failed, so the enumeration never ran and the WORST server escaped silently.
test('TLS reverse-gate: a server accepting ONLY TLS 1.0 still fires weak-tls (not invisible)', async () => {
  let key: Buffer, cert: Buffer
  try {
    const dir = mkdtempSync(join(tmpdir(), 'vt10-'))
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', join(dir, 'k'), '-out', join(dir, 'c'), '-days', '1', '-nodes', '-subj', '/CN=localhost'], { stdio: 'ignore' })
    key = readFileSync(join(dir, 'k')); cert = readFileSync(join(dir, 'c'))
  } catch { return } // openssl unavailable → soft-skip
  const srv = tls.createServer({ key, cert, minVersion: 'TLSv1', maxVersion: 'TLSv1', ciphers: 'DEFAULT@SECLEVEL=0' }, (s) => s.end()); srv.on('error', () => {})
  const tp = await new Promise<number>((r) => srv.listen(0, '127.0.0.1', () => r((srv.address() as net.AddressInfo).port)))
  try {
    const b = await scan('127.0.0.1', { authorized: true, ports: [tp], timeoutMs: 3000 })
    assert.ok(b.findings.some((f) => f.kind === 'weak-tls'), 'weak-tls fired on a TLS-1.0-only server (reverse gate closed)')
  } finally { srv.close() }
})
