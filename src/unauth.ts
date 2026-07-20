import net from 'node:net'
import { defang } from './fingerprint.js'
import type { NetFinding, PortResult } from './types.js'

/**
 * Unauthenticated-service detection — PROTOCOL-driven, not port-driven (the lesson
 * from the earlier port-keyed bug, applied here too). A service that expects auth
 * is a finding when it answers a benign hello WITHOUT credentials, wherever it
 * runs. We identify the candidate service three ways — the discovered fingerprint
 * (Redis on :31812 is still Redis), the well-known port, and (for a dark port that
 * volunteered nothing) a small rotation of distinctive text-protocol hellos — then
 * classify the reply: exposed (no auth → CRITICAL), authRequired (good), or
 * inconclusive (UNKNOWN, never "clean"). Read-only, one hello, authorized host only.
 */
interface UnauthProbe {
  service: string
  /** Well-known ports for this service. */
  ports: number[]
  /** Matches a discovered banner/product so the probe fires on ANY port. */
  fp?: RegExp
  /** Safe to try on an unidentified (dark) port — a distinctive, cheap protocol hello. */
  darkEligible?: boolean
  /** Bytes/string to send; a Buffer for binary protocols; null = just read the banner. */
  send: string | Buffer | null
  exposed: (resp: string) => boolean
  authRequired: (resp: string) => boolean
}

// Minimal MongoDB legacy OP_QUERY {isMaster:1} on admin.$cmd — enough to make an
// unauthenticated mongod answer with a document (maxWireVersion/ismaster).
function mongoIsMaster(): Buffer {
  const bson = Buffer.concat([
    Buffer.from([0x13, 0x00, 0x00, 0x00]), // doc len = 19
    Buffer.from([0x10]), Buffer.from('isMaster\0', 'latin1'), Buffer.from([0x01, 0x00, 0x00, 0x00]), // int32 isMaster=1
    Buffer.from([0x00]),
  ])
  const coll = Buffer.from('admin.$cmd\0', 'latin1')
  const body = Buffer.concat([
    Buffer.from([0x00, 0x00, 0x00, 0x00]), // flags
    coll,
    Buffer.from([0x00, 0x00, 0x00, 0x00]), // numberToSkip
    Buffer.from([0x01, 0x00, 0x00, 0x00]), // numberToReturn
    bson,
  ])
  const header = Buffer.alloc(16)
  header.writeInt32LE(16 + body.length, 0) // messageLength
  header.writeInt32LE(1, 4) // requestID
  header.writeInt32LE(0, 8) // responseTo
  header.writeInt32LE(2004, 12) // opCode OP_QUERY
  return Buffer.concat([header, body])
}

const HTTP_GET = (path: string): string => `GET ${path} HTTP/1.0\r\nHost: localhost\r\nUser-Agent: voyager-net\r\n\r\n`

// EVERY probe is darkEligible (Kimi round-3 #1): the hellos are innocuous read-only
// requests (a PING, a GET, an isMaster), so a datastore/admin service on an ARBITRARY
// port is caught the same as on its default one — Mongo on :27018, Elastic on :9999,
// etc. all get probed, not just Redis/Memcached/ZooKeeper.
const PROBES: UnauthProbe[] = [
  { service: 'Redis', ports: [6379], fp: /redis/i, darkEligible: true, send: 'PING\r\n', exposed: (r) => /\+PONG/.test(r), authRequired: (r) => /NOAUTH|WRONGPASS|-ERR[^\n]*auth/i.test(r) },
  { service: 'Memcached', ports: [11211], fp: /memcached/i, darkEligible: true, send: 'version\r\n', exposed: (r) => /^VERSION\s/i.test(r.trim()), authRequired: () => false },
  { service: 'ZooKeeper', ports: [2181], fp: /zookeeper/i, darkEligible: true, send: 'ruok', exposed: (r) => /imok/.test(r), authRequired: () => false },
  { service: 'MongoDB', ports: [27017], fp: /mongo/i, darkEligible: true, send: mongoIsMaster(), exposed: (r) => /ismaster|maxWireVersion|maxBsonObjectSize/i.test(r), authRequired: (r) => /auth|Unauthorized|not authorized/i.test(r) },
  { service: 'Elasticsearch', ports: [9200], fp: /elastic/i, darkEligible: true, send: HTTP_GET('/'), exposed: (r) => /"cluster_name"|"lucene_version"|"number_of_nodes"/.test(r), authRequired: (r) => /\b401\b|security_exception|missing authentication/i.test(r) },
  { service: 'CouchDB', ports: [5984], fp: /couchdb/i, darkEligible: true, send: HTTP_GET('/'), exposed: (r) => /"couchdb"\s*:\s*"Welcome"/.test(r), authRequired: (r) => /\b401\b|unauthorized/i.test(r) },
  { service: 'Docker Engine API', ports: [2375], fp: /docker/i, darkEligible: true, send: HTTP_GET('/version'), exposed: (r) => /"ApiVersion"|"DockerRootDir"|"GoVersion"/.test(r), authRequired: (r) => /\b401\b/.test(r) },
  { service: 'etcd', ports: [2379], fp: /etcd/i, darkEligible: true, send: HTTP_GET('/version'), exposed: (r) => /"etcdserver"|"etcdcluster"/.test(r), authRequired: (r) => /\b401\b|Unauthorized/i.test(r) },
  { service: 'Consul', ports: [8500], fp: /consul/i, darkEligible: true, send: HTTP_GET('/v1/status/leader'), exposed: (r) => /200 OK[\s\S]*"[\d.]+:\d+"/.test(r), authRequired: (r) => /ACL|\b403\b/i.test(r) },
  { service: 'Prometheus', ports: [9090], fp: /prometheus/i, darkEligible: true, send: HTTP_GET('/api/v1/status/buildinfo'), exposed: (r) => /"status"\s*:\s*"success"[\s\S]*prometheus|"version"/i.test(r), authRequired: (r) => /\b401\b/.test(r) },
  { service: 'RabbitMQ Management', ports: [15672], fp: /rabbitmq/i, darkEligible: true, send: HTTP_GET('/api/overview'), exposed: (r) => /"rabbitmq_version"|"management_version"/.test(r), authRequired: (r) => /\b401\b/.test(r) },
  { service: 'Kubernetes API', ports: [6443, 8080, 10250], fp: /kube|k8s/i, darkEligible: true, send: HTTP_GET('/version'), exposed: (r) => /"gitVersion"|"buildDate"[\s\S]*"platform"/.test(r), authRequired: (r) => /\b401\b|\b403\b|Unauthorized|forbidden/i.test(r) },
  // ── AI-NATIVE exposure (Kimi R3-3/R3-4): an open Ollama = model theft + arbitrary
  // inference; an open vector DB = the customers' embeddings in the clear. Our own turf.
  { service: 'Ollama (LLM server)', ports: [11434], fp: /ollama/i, darkEligible: true, send: HTTP_GET('/api/tags'), exposed: (r) => /"models"\s*:|"modified_at"|"digest"\s*:/.test(r), authRequired: (r) => /\b401\b|\b403\b/.test(r) },
  { service: 'Qdrant (vector DB)', ports: [6333], fp: /qdrant/i, darkEligible: true, send: HTTP_GET('/'), exposed: (r) => /"title"\s*:\s*"qdrant|qdrant[\s-]*(?:version|api)/i.test(r), authRequired: (r) => /\b401\b|\b403\b|api[- ]key/i.test(r) },
  { service: 'Weaviate (vector DB)', ports: [8080], fp: /weaviate/i, darkEligible: true, send: HTTP_GET('/v1/meta'), exposed: (r) => /"hostname"[\s\S]*"version"|"modules"\s*:/.test(r), authRequired: (r) => /\b401\b|\b403\b/.test(r) },
  { service: 'ChromaDB (vector DB)', ports: [8000], fp: /chroma/i, darkEligible: true, send: HTTP_GET('/api/v1/heartbeat'), exposed: (r) => /nanosecond.?heartbeat/i.test(r), authRequired: (r) => /\b401\b|\b403\b/.test(r) },
  { service: 'MQTT broker', ports: [1883], fp: /mqtt|mosquitto/i, darkEligible: true, send: mqttConnect(), exposed: (r) => r.charCodeAt(0) === 0x20 && r.length >= 4 && r.charCodeAt(3) === 0x00, authRequired: (r) => r.charCodeAt(0) === 0x20 && r.length >= 4 && (r.charCodeAt(3) === 0x04 || r.charCodeAt(3) === 0x05) },
]

/** A minimal MQTT v3.1.1 CONNECT packet (clean session, client-id "voyager"). An
 *  anonymous broker replies CONNACK with return code 0x00 (accepted). */
function mqttConnect(): Buffer {
  const clientId = Buffer.from('voyager', 'latin1')
  const varHeader = Buffer.concat([Buffer.from([0x00, 0x04]), Buffer.from('MQTT', 'latin1'), Buffer.from([0x04, 0x02, 0x00, 0x3c])])
  const payload = Buffer.concat([Buffer.from([0x00, clientId.length]), clientId])
  const body = Buffer.concat([varHeader, payload])
  return Buffer.concat([Buffer.from([0x10, body.length]), body])
}

/** Ports worth adding to the default sweep because they host unauth-prone services. */
export const UNAUTH_PORTS = [...new Set(PROBES.flatMap((p) => p.ports))]

/**
 * Probe open ports for missing authentication. `inspectedPorts` are the ports that
 * already answered TLS/HTTP (so we don't re-probe them blindly); anything open,
 * un-fingerprinted and NOT in that set is a "dark" port that gets the distinctive
 * text-protocol hellos. Returns one finding per exposed service.
 */
export async function scanUnauth(pin: string, host: string, open: PortResult[], timeoutMs: number, inspectedPorts: Set<number> = new Set(), httpPorts: Set<number> = new Set()): Promise<NetFinding[]> {
  const jobs: Array<Promise<NetFinding | null>> = []
  const isHttpProbe = (pr: UnauthProbe): boolean => typeof pr.send === 'string' && pr.send.startsWith('GET ')
  for (const p of open) {
    const id = `${p.product ?? ''} ${p.service ?? ''} ${p.banner ?? ''}`.trim()
    const isDark = !p.product && !p.banner && !inspectedPorts.has(p.port)
    const isHttp = httpPorts.has(p.port)
    // Which probes apply to THIS port: exact port, fingerprint match anywhere, the
    // cheap text-protocol hellos on a dark port, OR — the fix — the HTTP-GET probes
    // on ANY port that already answered HTTP (Ollama/Qdrant/Weaviate/… speak HTTP on
    // arbitrary ports, so they're never "dark" and were being skipped, Kimi R3-3/R3-4).
    // EXACT matches (port / fingerprint / HTTP-answered) come FIRST and are never
    // truncated; the generic dark-port hellos fill the rest up to the cap. Without
    // this a port-specific probe near the end of the list (e.g. MQTT) got cut when
    // the dark rotation grew.
    const exact = PROBES.filter((pr) => pr.ports.includes(p.port) || (id && pr.fp?.test(id)) || (isHttp && isHttpProbe(pr)))
    const darkOnly = isDark ? PROBES.filter((pr) => pr.darkEligible && !exact.includes(pr)) : []
    const seen = new Set<string>()
    const chosen = [...exact, ...darkOnly].filter((pr) => (seen.has(pr.service) ? false : (seen.add(pr.service), true))).slice(0, isDark || isHttp ? 18 : 5)
    for (const probe of chosen) jobs.push(runProbe(pin, host, p.port, probe, timeoutMs))
  }
  const out = await Promise.all(jobs)
  // Keep at most one finding per host:port (prefer a CRITICAL exposed over auth-ok).
  const byAt = new Map<string, NetFinding>()
  for (const f of out) {
    if (!f) continue
    const at = f.at ?? f.kind
    const prev = byAt.get(at)
    if (!prev || (f.severity === 'critical' && prev.severity !== 'critical')) byAt.set(at, f)
  }
  return [...byAt.values()]
}

async function runProbe(pin: string, host: string, port: number, probe: UnauthProbe, timeoutMs: number): Promise<NetFinding | null> {
  const resp = await talk(pin, port, probe.send, timeoutMs)
  if (resp == null) return null
  if (probe.exposed(resp)) {
    return {
      severity: 'critical', kind: 'unauthenticated-service',
      detail: `${probe.service} answered a protocol probe WITHOUT authentication — exposed on port ${port} (framed reply: ${defang(resp.replace(/[^\x20-\x7e]+/g, ' ').trim().slice(0, 80))})`,
      at: `${host}:${port}`,
      suggestedFix: `require authentication on ${probe.service} and firewall the port to trusted networks — an unauthenticated ${probe.service} is remote data access / RCE-adjacent`,
      confidence: 'strong',
    }
  }
  if (probe.authRequired(resp)) {
    return { severity: 'info', kind: 'service-auth-ok', detail: `${probe.service} required authentication (probe rejected) — good`, at: `${host}:${port}`, suggestedFix: 'no action — not anonymously exposed', confidence: 'moderate' }
  }
  return null
}

/** One benign request/response over raw TCP, pinned to the vetted IP. */
function talk(ip: string, port: number, send: string | Buffer | null, timeoutMs: number): Promise<string | null> {
  return new Promise((resolve) => {
    const sock = new net.Socket()
    let buf = ''
    let done = false
    const finish = (v: string | null): void => {
      if (done) return
      done = true
      try { sock.destroy() } catch { /* noop */ }
      resolve(v)
    }
    sock.setTimeout(timeoutMs)
    sock.once('timeout', () => finish(buf || null))
    sock.once('error', () => finish(buf || null))
    sock.once('connect', () => { if (send) sock.write(send) })
    sock.on('data', (d) => { buf += d.toString('latin1'); if (buf.length > 8192) finish(buf) })
    sock.once('close', () => finish(buf || null))
    try { sock.connect(port, ip) } catch { finish(null) }
  })
}
