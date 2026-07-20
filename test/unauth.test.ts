import { test } from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import { scanUnauth } from '../dist/unauth.js'

/** Try to bind a mock service on a well-known port (so scanUnauth's port table
 *  applies). Resolves null if the port is busy — the test then soft-skips. */
function bindMock(port: number, reply: (chunk: string) => string | null): Promise<net.Server | null> {
  return new Promise((resolve) => {
    const server = net.createServer((sock) => {
      sock.on('data', (d) => { const r = reply(d.toString()); if (r) sock.write(r) })
    })
    server.once('error', () => resolve(null))
    server.listen(port, '127.0.0.1', () => resolve(server))
  })
}
const openPort = (port: number) => [{ port, state: 'open', open: true } as never]

test('scanUnauth: an unauthenticated Redis (PING → +PONG) is a CRITICAL finding', async () => {
  const server = await bindMock(6379, (c) => (/PING/.test(c) ? '+PONG\r\n' : null))
  if (!server) return // 6379 busy in this sandbox → soft-skip
  try {
    const findings = await scanUnauth('127.0.0.1', 'localhost', openPort(6379), 1500)
    const f = findings.find((x) => x.kind === 'unauthenticated-service')
    assert.ok(f, 'exposed Redis yields an unauthenticated-service finding')
    assert.equal(f!.severity, 'critical')
    assert.match(f!.detail, /Redis/)
  } finally {
    server.close()
  }
})

test('scanUnauth: a Redis that DEMANDS auth (NOAUTH) is NOT flagged critical', async () => {
  const server = await bindMock(6379, (c) => (/PING/.test(c) ? '-NOAUTH Authentication required.\r\n' : null))
  if (!server) return
  try {
    const findings = await scanUnauth('127.0.0.1', 'localhost', openPort(6379), 1500)
    assert.ok(!findings.some((x) => x.kind === 'unauthenticated-service'), 'auth-required Redis is not exposed')
  } finally {
    server.close()
  }
})

test('scanUnauth: a port with no matching service probe yields nothing, never throws', async () => {
  const findings = await scanUnauth('127.0.0.1', 'localhost', openPort(12345), 300)
  assert.deepEqual(findings, [])
})

// Kimi #1: PROTOCOL over PORT — a dark (un-fingerprinted) port gets the text-protocol
// hellos, so Redis on a NON-standard port is still caught.
test('scanUnauth: Redis on a NON-standard, un-fingerprinted port is still CRITICAL (protocol > port)', async () => {
  const srv = await bindMock(31812, (c) => (/PING/i.test(c) ? '+PONG\r\n' : null))
  if (!srv) return // port busy → soft-skip
  try {
    // A bare open port with NO product/banner and not in inspectedPorts = dark.
    const findings = await scanUnauth('127.0.0.1', 'localhost', [{ port: 31812, state: 'open', open: true }], 1500, new Set())
    assert.ok(findings.some((f) => f.kind === 'unauthenticated-service' && /31812/.test(f.at ?? '')), 'dark-port Redis detected by protocol hello, not port table')
  } finally {
    srv.close()
  }
})

test('UNAUTH_PORTS includes the cloud-native set (mongo/etcd/consul/prometheus/rabbitmq/k8s)', async () => {
  const { UNAUTH_PORTS } = await import('../dist/unauth.js')
  for (const p of [27017, 2379, 8500, 9090, 15672, 6443]) assert.ok(UNAUTH_PORTS.includes(p), `port ${p} covered`)
})
