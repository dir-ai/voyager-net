import { Resolver } from 'node:dns/promises'
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

  return {
    a: a ?? [],
    aaaa: aaaa ?? [],
    mx: (mx ?? []).map((m) => `${m.exchange} (${m.priority})`),
    txt: txtFlat.slice(0, 20),
    caa: (caa ?? []).map((c) => JSON.stringify(c)).slice(0, 10),
    hasSpf: txtFlat.some((t) => /^v=spf1/i.test(t)),
    hasDmarc: dmarcFlat.some((t) => /^v=DMARC1/i.test(t)),
    hasCaa: (caa ?? []).length > 0,
  }
}
