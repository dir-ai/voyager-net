import { stripInjection } from '@dir-ai/voyager'

/** Defang target-controlled text so a hostile banner/header can't smuggle a live,
 *  clickable/executable-looking URL or command into the brief. http→hxxp, dot→[.],
 *  and known download-and-run shapes are neutered. Purely cosmetic-safety. */
export function defang(s: string): string {
  return s
    .replace(/\bhttps?:\/\//gi, (m) => m.replace(/t/gi, 'x'))
    .replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, '$1[.]$2[.]$3[.]$4')
    .replace(/\|\s*(sh|bash|zsh|python\d?)\b/gi, '| [defanged-$1]')
}

export interface Fingerprint {
  /** The volunteered banner, injection-stripped and bounded. */
  banner: string
  product?: string
  version?: string
}

// PASSIVE fingerprints: we never send a probe — we only interpret what the
// service volunteered on connect. Each rule pulls a product (+ version) from a
// banner shape. Order matters: the specific protocols before the generic catch.
const RULES: Array<{ re: RegExp; product: (m: RegExpMatchArray) => string; version?: (m: RegExpMatchArray) => string | undefined }> = [
  // SSH-2.0-OpenSSH_8.9p1 Ubuntu-...
  { re: /^SSH-\d+\.\d+-(\S+)/, product: (m) => productOf(m[1]), version: (m) => versionOf(m[1]) },
  // 220 ... ESMTP Postfix / Exim / Sendmail
  { re: /\b(Postfix|Exim|Sendmail|OpenSMTPD|Microsoft ESMTP)\b(?:[^\d\n]*(\d[\d.]*))?/i, product: (m) => m[1], version: (m) => m[2] },
  // 220 (vsFTPd 3.0.3) / ProFTPD / Pure-FTPd / FileZilla
  { re: /\b(vsFTPd|ProFTPD|Pure-FTPd|FileZilla|FTP)\b[^\d\n]*(\d[\d.]*)?/i, product: (m) => m[1], version: (m) => m[2] },
  // +OK Dovecot / Cyrus (POP3/IMAP)
  { re: /\b(Dovecot|Cyrus|Courier)\b[^\d\n]*(\d[\d.]*)?/i, product: (m) => m[1], version: (m) => m[2] },
  // Redis volunteers nothing, but a NOAUTH/ERR line reveals it if present
  { re: /\bRedis\b[^\d\n]*(\d[\d.]*)?/i, product: () => 'Redis', version: (m) => m[1] },
]

function productOf(token: string): string {
  const m = /^([A-Za-z][A-Za-z+.-]*?)[_/-]?\d/.exec(token)
  return m ? m[1] : token
}
function versionOf(token: string): string | undefined {
  const m = /(\d[\w.]*)/.exec(token)
  return m ? m[1] : undefined
}

/** Turn a volunteered banner into a framed fingerprint. Never sends anything. */
export function fingerprintBanner(raw: string, _port: number): Fingerprint {
  // Strip control bytes, keep the first line, frame it (untrusted content).
  const firstLine = (raw.split(/\r|\n/)[0] ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ')
  const banner = defang(stripInjection(firstLine)).trim().slice(0, 200)
  if (!banner) return { banner: '' }
  for (const rule of RULES) {
    const m = banner.match(rule.re)
    if (m) {
      const product = rule.product(m)
      const version = rule.version?.(m)
      return { banner, product: product || undefined, version: version || undefined }
    }
  }
  return { banner }
}
