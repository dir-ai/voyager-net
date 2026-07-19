import { Resolver } from 'node:dns/promises'
import { stripInjection } from '@dir-ai/voyager'
import type { DnsInfo } from './types.js'

/** Read-only DNS introspection for a domain: records + email/CA hygiene. */
export async function scanDns(domain: string, timeoutMs = 5000): Promise<DnsInfo> {
  const r = new Resolver({ timeout: timeoutMs, tries: 2 })
  const safe = async <T>(p: Promise<T>): Promise<T | null> => p.catch(() => null)

  const [a, aaaa, mx, txt, caa, dmarcTxt] = await Promise.all([
    safe(r.resolve4(domain)),
    safe(r.resolve6(domain)),
    safe(r.resolveMx(domain)),
    safe(r.resolveTxt(domain)),
    safe(r.resolveCaa(domain)),
    safe(r.resolveTxt(`_dmarc.${domain}`)),
  ])

  const txtFlat = (txt ?? []).map((chunks) => chunks.join(''))
  const dmarcFlat = (dmarcTxt ?? []).map((chunks) => chunks.join(''))
  // Records are TARGET-controlled (any domain you point the tool at) — a TXT
  // record is an ideal injection carrier. Frame every record string before it
  // enters the brief the agent consumes; keep the RAW value for hygiene tests.
  const fr = (s: string): string => stripInjection(s).slice(0, 300)

  return {
    a: a ?? [],
    aaaa: aaaa ?? [],
    mx: (mx ?? []).map((m) => `${fr(m.exchange)} (${m.priority})`),
    txt: txtFlat.map(fr).slice(0, 20),
    caa: (caa ?? []).map((c) => fr(JSON.stringify(c))).slice(0, 10),
    hasSpf: txtFlat.some((t) => /^v=spf1/i.test(t)),
    hasDmarc: dmarcFlat.some((t) => /^v=DMARC1/i.test(t)),
    hasCaa: (caa ?? []).length > 0,
    spf: txtFlat.find((t) => /^v=spf1/i.test(t)) ?? null,
    dmarc: dmarcFlat.find((t) => /^v=DMARC1/i.test(t)) ?? null,
  }
}
