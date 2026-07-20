import { test } from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import { fingerprintDb } from '../dist/dbfingerprint.js'

test('fingerprintDb: parses a MySQL greeting (protocol 10 + version) on any port', async () => {
  const srv = net.createServer((s) => {
    const version = Buffer.from('8.0.32-mysql\0', 'latin1')
    const payload = Buffer.concat([Buffer.from([0x0a]), version, Buffer.alloc(20, 0)])
    const head = Buffer.alloc(4); head.writeUIntLE(payload.length, 0, 3)
    s.write(Buffer.concat([head, payload]))
  })
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()))
  const port = (srv.address() as net.AddressInfo).port
  try {
    const findings = await fingerprintDb('127.0.0.1', 'localhost', [{ port, state: 'open', open: true }], new Set(), 2000)
    assert.ok(findings.some((f) => /MySQL/.test(f.detail) && /8\.0\.32/.test(f.detail)), 'MySQL version identified')
  } finally { srv.close() }
})
