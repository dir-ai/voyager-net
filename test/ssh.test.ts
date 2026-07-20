import { test } from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import { inspectSsh } from '../dist/ssh.js'

function nameList(s: string): Buffer { const b = Buffer.from(s, 'latin1'); const len = Buffer.alloc(4); len.writeUInt32BE(b.length, 0); return Buffer.concat([len, b]) }
function kexinit(): Buffer {
  const payload = Buffer.concat([
    Buffer.from([20]), Buffer.alloc(16, 7),
    nameList('diffie-hellman-group1-sha1,curve25519-sha256'),
    nameList('ssh-rsa,ssh-ed25519'),
    nameList('aes128-cbc,chacha20-poly1305@openssh.com'), nameList('aes128-cbc'),
    nameList('hmac-md5,hmac-sha2-256'), nameList('hmac-md5'),
    nameList('none'), nameList('none'), nameList(''), nameList(''),
    Buffer.from([0]), Buffer.alloc(4, 0),
  ])
  let padLen = 8 - ((5 + payload.length) % 8); if (padLen < 4) padLen += 8
  const pad = Buffer.alloc(padLen, 0)
  const head = Buffer.alloc(5); head.writeUInt32BE(1 + payload.length + pad.length, 0); head.writeUInt8(pad.length, 4)
  return Buffer.concat([head, payload, pad])
}

test('inspectSsh: parses the server KEXINIT and flags weak kex/host-key/cipher/MAC', async () => {
  const srv = net.createServer((s) => { s.write('SSH-2.0-FakeSSH\r\n'); s.write(kexinit()) })
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r))
  const port = (srv.address() as net.AddressInfo).port
  try {
    const findings = await inspectSsh('127.0.0.1', 'localhost', port, 2000)
    const detail = findings.map((f) => f.detail).join(' | ')
    assert.ok(/diffie-hellman-group1-sha1/.test(detail), 'weak kex flagged')
    assert.ok(/ssh-rsa/.test(detail), 'weak host key flagged')
    assert.ok(/aes128-cbc/.test(detail), 'CBC cipher flagged')
    assert.ok(/hmac-md5/.test(detail), 'MD5 MAC flagged')
    assert.ok(findings.every((f) => f.kind === 'ssh-weak-algorithm'))
  } finally { srv.close() }
})
