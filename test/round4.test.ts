import { test } from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import http from 'node:http'
import { scanUnauth, scanVnc } from '../dist/index.js'

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
