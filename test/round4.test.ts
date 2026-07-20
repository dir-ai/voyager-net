import { test } from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import http from 'node:http'
import { scanUnauth, scanVnc, scanAxfr, inspectTelnet, inspectRdp } from '../dist/index.js'

test('scanUnauth: Ollama on a NONSTANDARD HTTP port is caught (AI-native exposure)', async () => {
  const srv = http.createServer((q, r) => { if (/\/api\/tags/.test(q.url ?? '')) { r.writeHead(200); r.end('{"models":[{"name":"llama3","modified_at":"2024","digest":"x"}]}') } else r.end('{}') })
  srv.on('clientError', () => {})
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()))
  const port = (srv.address() as net.AddressInfo).port
  try {
    const f = await scanUnauth('127.0.0.1', 'localhost', [{ port, state: 'open', open: true }], 2500, new Set(), new Set([port]))
    assert.ok(f.some((x) => x.kind === 'unauthenticated-service' && /Ollama/.test(x.detail)), 'Ollama flagged on a non-11434 port')
  } finally { srv.close() }
})

test('scanUnauth: an anonymous MQTT broker (CONNACK 0x00) is CRITICAL', async () => {
  const srv = net.createServer((s) => { s.on('error', () => {}); s.on('data', () => s.write(Buffer.from([0x20, 0x02, 0x00, 0x00]))) })
  srv.on('error', () => {})
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()))
  const port = (srv.address() as net.AddressInfo).port
  try {
    const f = await scanUnauth('127.0.0.1', 'localhost', [{ port, state: 'open', open: true }], 2500, new Set(), new Set())
    assert.ok(f.some((x) => x.kind === 'unauthenticated-service' && /MQTT/.test(x.detail)))
  } finally { srv.close() }
})

test('scanVnc: an RFB server offering security type None is CRITICAL', async () => {
  const srv = net.createServer((s) => { s.on('error', () => {}); s.write('RFB 003.008\n'); s.once('data', () => s.write(Buffer.from([0x01, 0x01]))) })
  srv.on('error', () => {})
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()))
  const port = (srv.address() as net.AddressInfo).port
  try {
    const f = await scanVnc('127.0.0.1', 'localhost', [{ port, state: 'open', open: true }], new Set(), 2500)
    assert.ok(f.some((x) => x.kind === 'unauthenticated-service' && /VNC/.test(x.detail)))
  } finally { srv.close() }
})

test('scanAxfr: a server that answers AXFR (ANCOUNT>0, NoError) is a zone-transfer finding', async () => {
  const srv = net.createServer((s) => { s.on('error', () => {}); s.on('data', () => { const m = Buffer.alloc(20); m.writeUInt16BE(0x8400, 2); m.writeUInt16BE(1, 4); m.writeUInt16BE(2, 6); const f = Buffer.alloc(2 + m.length); f.writeUInt16BE(m.length, 0); m.copy(f, 2); s.write(f) }) })
  srv.on('error', () => {})
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()))
  const port = (srv.address() as net.AddressInfo).port
  try { assert.ok((await scanAxfr('127.0.0.1', 'ex.com', 'ex.com', port, 2500)).some((x) => x.kind === 'zone-transfer')) } finally { srv.close() }
})

test('inspectTelnet: an exposed Telnet is a cleartext finding', async () => {
  const srv = net.createServer((s) => { s.on('error', () => {}); s.write('login: ') }); srv.on('error', () => {})
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()))
  const port = (srv.address() as net.AddressInfo).port
  try { assert.ok((await inspectTelnet('127.0.0.1', 'localhost', port, 2000)).some((x) => x.kind === 'telnet-cleartext')) } finally { srv.close() }
})

test('inspectRdp: a server accepting Standard RDP Security (selectedProtocol 0) → no-NLA', async () => {
  const srv = net.createServer((s) => { s.on('error', () => {}); s.once('data', () => { const neg = Buffer.from([0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]); const x = Buffer.concat([Buffer.from([6 + neg.length, 0xd0, 0, 0, 0, 0, 0]), neg]); s.write(Buffer.concat([Buffer.from([0x03, 0x00, 0x00, 4 + x.length]), x])) }) }); srv.on('error', () => {})
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()))
  const port = (srv.address() as net.AddressInfo).port
  try { assert.ok((await inspectRdp('127.0.0.1', 'localhost', port, 2500)).some((x) => x.kind === 'rdp-no-nla')) } finally { srv.close() }
})
