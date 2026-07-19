#!/usr/bin/env node
/**
 * voyager-net MCP server (stdio). One tool: scan_host — safe, read-only,
 * AUTHORIZED introspection of a single host/domain. Fail-closed: without
 * `authorized: true` it refuses (isError). Never applies a fix, exploits, or
 * scans ranges.
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import { scan } from './scan.js'
import type { ScanOptions } from './types.js'
import { VERSION } from './version.js'

const server = new Server({ name: 'voyager-net', version: VERSION }, { capabilities: { tools: {} } })

const TOOLS = [
  {
    name: 'scan_host',
    description:
      "Read-only, AUTHORIZED introspection of ONE host or domain you own: DNS records + email/CA hygiene, open ports, TLS certificate posture, and HTTP security headers → findings with DESCRIBED (never applied) fixes. FAIL-CLOSED: requires authorized:true (you assert ownership/permission). Refuses CIDR ranges, lists, URLs, and cloud metadata endpoints. Never exploits, floods, or mutates. isError:true means the scan could not run (not authorized / invalid target / error), not that the host is clean.",
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        target: { type: 'string', minLength: 1, maxLength: 253, description: 'A single host or domain you own.' },
        authorized: { type: 'boolean', description: 'You assert you own / are permitted to test this target. Required.' },
        ports: { type: 'array', items: { type: 'integer', minimum: 1, maximum: 65535 }, maxItems: 64 },
        timeoutMs: { type: 'integer', minimum: 500, maximum: 15000 },
      },
      required: ['target'],
    },
  },
] as const

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }))

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params
  const a = args as Record<string, unknown>
  const ok = (data: unknown, isError = false) => ({ content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }], ...(isError ? { isError: true } : {}) })
  const err = (message: string) => ok({ error: message }, true)

  try {
    if (name === 'scan_host') {
      const target = typeof a.target === 'string' ? a.target.slice(0, 253) : ''
      if (!target) return err('target required')
      const ports = Array.isArray(a.ports) ? a.ports.filter((p): p is number => typeof p === 'number' && Number.isInteger(p)).slice(0, 64) : undefined
      const timeoutMs = typeof a.timeoutMs === 'number' && Number.isInteger(a.timeoutMs) ? a.timeoutMs : undefined
      const opts: ScanOptions = { authorized: a.authorized === true, ports, timeoutMs }
      const brief = await scan(target, opts)
      return ok(brief, Boolean(brief.error))
    }
    return err(`Unknown tool: ${name}`)
  } catch (e) {
    return err(e instanceof Error ? e.message : String(e))
  }
})

export async function startMcpServer(): Promise<void> {
  const transport = new StdioServerTransport()
  await server.connect(transport)
  console.error(`voyager-net MCP server v${VERSION} ready (stdio)`)
}

import { fileURLToPath } from 'node:url'
import { realpathSync } from 'node:fs'
function isDirectEntry(): boolean {
  const argv1 = process.argv[1]
  if (!argv1) return false
  const self = fileURLToPath(import.meta.url)
  try {
    return realpathSync(self) === realpathSync(argv1)
  } catch {
    return self === argv1
  }
}
if (isDirectEntry()) {
  startMcpServer().catch((e) => {
    console.error(e instanceof Error ? e.stack : String(e))
    process.exit(1)
  })
}
