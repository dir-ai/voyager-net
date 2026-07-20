import { test } from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import tls from 'node:tls'
import http from 'node:http'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { scan, scanUnauth } from '../dist/index.js'
import { scanFtp } from '../dist/ftp.js'
import { scanRsyncModules } from '../dist/rsync.js'
import { scanHttpExposure } from '../dist/httpexpose.js'

/** Generate a throwaway self-signed cert, or null if openssl is unavailable. */
function makeCert(): { key: Buffer; cert: Buffer } | null {
  try {
    const dir = mkdtempSync(join(tmpdir(), 'vc-'))
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', join(dir, 'k'), '-out', join(dir, 'c'), '-days', '1', '-nodes', '-subj', '/CN=localhost'], { stdio: 'ignore' })
    return { key: readFileSync(join(dir, 'k')), cert: readFileSync(join(dir, 'c')) }
  } catch { return null }
}

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

// Kimi Canto VI #36: a service that speaks ONLY over TLS (k8s API :6443) was invisible
// because the unauth probes only spoke cleartext. TLS-wrapped probes now reach it.
test('unauth TLS-aware: a Kubernetes API behind TLS is caught (probe wrapped in TLS)', async () => {
  const c = makeCert(); if (!c) return // openssl unavailable → soft-skip
  const k8s = tls.createServer({ key: c.key, cert: c.cert }, (s) => {
    s.on('error', () => {})
    s.on('data', () => s.end('HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{"major":"1","gitVersion":"v1.29.0","buildDate":"2026-01-01T00:00:00Z","platform":"linux/amd64"}'))
  }); k8s.on('error', () => {})
  const tp = await bind(k8s)
  try {
    const f = await scanUnauth('127.0.0.1', 'h', [{ port: tp, state: 'open', open: true }], 3000, new Set([tp]), new Set(), new Set([tp]))
    assert.ok(f.some((x) => /Kubernetes/i.test(x.detail) && x.kind === 'unauthenticated-service'), 'k8s-over-TLS detected via a TLS-wrapped probe')
  } finally { k8s.close() }
})

// Kimi Canto VI #34: FTP anonymous login (USER anonymous → 230), not just the version.
test('scanFtp: anonymous FTP login (USER anonymous → 230) is flagged', async () => {
  const ftp = net.createServer((s) => {
    s.on('error', () => {}); s.write('220 Test FTP ready\r\n')
    s.on('data', (d) => { const t = d.toString(); if (/USER/i.test(t)) s.write('331 password please\r\n'); else if (/PASS/i.test(t)) s.write('230 Login successful.\r\n'); else if (/QUIT/i.test(t)) s.end('221 Bye\r\n') })
  }); ftp.on('error', () => {})
  const fp = await bind(ftp)
  try { assert.ok((await scanFtp('127.0.0.1', 'h', fp, 2500)).some((x) => x.kind === 'ftp-anonymous')) } finally { ftp.close() }
})

// Kimi Canto VI #31 (deep): rsync module ENUMERATION beyond the banner.
test('scanRsyncModules: an rsync daemon that lists anonymous modules is flagged', async () => {
  const rsync = net.createServer((s) => {
    s.on('error', () => {}); s.write('@RSYNCD: 31.0\n')
    s.on('data', () => s.write('share1\tPublic share\nbackups\tNightly backups\n@RSYNCD: EXIT\n'))
  }); rsync.on('error', () => {})
  const rp = await bind(rsync)
  try {
    const f = await scanRsyncModules('127.0.0.1', 'h', rp, 2500)
    assert.ok(f.some((x) => x.kind === 'rsync-anonymous-module' && /share1/.test(x.detail)))
  } finally { rsync.close() }
})

// Kimi Canto VI #35: Apache mod_status (/server-status) world-readable.
test('scanHttpExposure: Apache /server-status world-readable is flagged', async () => {
  const web = http.createServer((req, res) => {
    if ((req.url ?? '').startsWith('/server-status')) { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('Total Accesses: 42\nBusyWorkers: 1\nScoreboard: ____W____') }
    else { res.writeHead(404); res.end('not found') }
  }); web.on('error', () => {})
  const wp = await bind(web)
  try { assert.ok((await scanHttpExposure('127.0.0.1', 'h', wp, false, 2500)).some((x) => x.kind === 'apache-server-status')) } finally { web.close() }
})
