export const meta = {
  name: 'hardening-review',
  description: 'Idiom audit of the whole Rust tree against HARDENING.md, each finding verified at its lines',
  phases: [
    { title: 'Review', detail: 'one reviewer per area, read-only' },
    { title: 'Verify', detail: 'one skeptic per area re-reads every finding' },
    { title: 'Synthesize', detail: 'rank the classes and the structural changes' },
  ],
}

const ROOT = '/home/kov/Projects/curl'
const C = `${ROOT}/crates`

const AREAS = [
  { key: 'http', paths: `${C}/curl-core/src/proto/http.rs, proto/http/ (h2.rs, h3.rs, rtsp.rs, negotiate.rs, sigv4.rs, ...), proto/http1/, proto/ws.rs and proto/ws/, src/http2/, src/http3/, src/http2.rs, src/http3.rs` },
  { key: 'line-protocols', paths: `${C}/curl-core/src/proto/ except http*: ftp, ssh (mod.rs, libssh2.rs, hostkey.rs, path.rs), smtp, imap, pop3, ldap, telnet, tftp, dict, mqtt, gopher, file, sasl users, proto/base.rs, proto/mod.rs` },
  { key: 'conn', paths: `${C}/curl-core/src/conn/ (route and reuse in mod.rs, pool, connect, dns, tls glue, line, h2proxy, layers)` },
  { key: 'multi', paths: `${C}/curl-core/src/multi/ (state.rs, state/ leg, tunnel, h2tunnel, socks, haproxy, connecting, tls; doh; the step context), src/share.rs, src/doh.rs` },
  { key: 'core-data', paths: `${C}/curl-core/src/ auth/, url/, options/, deliver/, upload/, mime/, cookie.rs, hsts.rs, altsvc.rs, netrc.rs, easy.rs, handler.rs, report.rs, progress/, date.rs, bufq.rs` },
  { key: 'tls-openssl', paths: `${C}/curl-core/src/tls.rs and tls/ (checked.rs, identity, residuals, session cache), and ${C}/curl-openssl/` },
  { key: 'tls-others', paths: `${C}/curl-gnutls/, curl-wolfssl/, curl-mbedtls/, curl-rustls/, curl-schannel/, curl-tls-native/` },
  { key: 'bindings', paths: `${C}/curl-ngtcp2/, curl-quiche/, curl-nghttp2/, curl-libssh/, curl-libssh2/, curl-ldap/, curl-ares/, curl-gssapi/, curl-sspi/, curl-idn2/, curl-psl/, curl-zlib/, curl-brotli/, curl-zstd/` },
  { key: 'shim', paths: `${C}/curl-sys-abi/ (the C ABI: easy.rs, multi.rs, setopt/, getinfo.rs, gate/, callbacks.rs, share, mime, url API)` },
  { key: 'tool', paths: `${C}/curl-tool/ (argument parsing, config files, output naming and writing, globbing, parallel transfers, --next)` },
  { key: 'os-alloc', paths: `${C}/curl-os/, curl-alloc/, curl-backends/, curl-build/` },
]

const BRIEF = `You are reviewing a Rust rewrite of curl and libcurl for vulnerability classes, read-only.
The project's goal is to have fewer vulnerabilities than the C: memory safety is given, the
target is logic bugs (credentials to the wrong host, connections reused with different set-up,
lengths that disagree with their bytes, peer-reachable aborts, callback re-entrancy).

First read ${ROOT}/HARDENING.md (the patterns and the idiom-audit checklist) and the "Why Rust"
section of ${ROOT}/CLAUDE.md. Then audit your area for every instance of those patterns. Read the
code itself: grep to find candidates, then read the surrounding function and its callers before
deciding. Also report anything else that a hostile peer, a hostile URL or file, or an application
misusing the API from a callback could turn into a wrong result, an abort, a hang, or data going
where it should not.

Rules:
- Read-only. Do not build, test, run cargo, or edit any file.
- Every finding cites file:line in the current tree and quotes the line(s).
- For each finding say: the pattern (or "other"), the concrete failure (inputs -> wrong outcome),
  whether it is reachable today and by whom (peer, URL, application, callback), and how sure you
  are; and the structural fix (a type or ownership change) if one exists, else the patch.
- Say whether C behaves the same where you can tell from ${ROOT}/lib/ (C source is there); mark
  "same as C" or "Rust only" or "unknown".
- Skip findings already recorded as deliberate in ${ROOT}/DIVERGENCE.md unless the record is wrong.
- Do not pad: an area with three real findings reports three. Prefer reachable over theoretical.`

const FINDINGS = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          file: { type: 'string' },
          line: { type: 'integer' },
          quote: { type: 'string' },
          pattern: { type: 'string' },
          failure: { type: 'string' },
          reachable: { type: 'string' },
          c_same: { type: 'string', enum: ['same as C', 'Rust only', 'unknown'] },
          fix: { type: 'string' },
          confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
        },
        required: ['title', 'file', 'line', 'quote', 'pattern', 'failure', 'reachable', 'c_same', 'fix', 'confidence'],
      },
    },
  },
  required: ['findings'],
}

const VERDICTS = {
  type: 'object',
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          verdict: { type: 'string', enum: ['confirmed', 'plausible', 'refuted'] },
          reason: { type: 'string' },
          severity: { type: 'string', enum: ['high', 'medium', 'low'] },
          c_same: { type: 'string', enum: ['same as C', 'Rust only', 'unknown'] },
        },
        required: ['title', 'verdict', 'reason', 'severity', 'c_same'],
      },
    },
  },
  required: ['verdicts'],
}

const results = await pipeline(
  AREAS,
  a => agent(`${BRIEF}\n\nYour area (${a.key}): ${a.paths}`, {
    label: `review:${a.key}`, phase: 'Review', schema: FINDINGS,
  }),
  (r, a) => {
    const fs = (r && r.findings) || []
    if (!fs.length) return { area: a.key, findings: [], verdicts: [] }
    return agent(`You are a skeptic checking another reviewer's findings on a Rust rewrite of curl,
read-only (no builds, no edits). For each finding below, open the cited file at the cited line in
${ROOT}/crates and decide: "confirmed" (the failure happens as described, reachable as claimed),
"plausible" (the code is as described but reachability or impact is unproven), or "refuted"
(the code does not say that, an earlier check prevents it, or it is recorded as deliberate in
${ROOT}/DIVERGENCE.md). Trace the callers far enough to know. Default to refuted when the
evidence is not in the code. Check the C claim against ${ROOT}/lib/ where you can. Severity is
for a library embedded in applications facing hostile peers.

Findings (area ${a.key}):
${JSON.stringify(fs, null, 1)}`, {
      label: `verify:${a.key}`, phase: 'Verify', schema: VERDICTS,
    }).then(v => ({ area: a.key, findings: fs, verdicts: (v && v.verdicts) || [] }))
  },
)

const kept = []
for (const r of results.filter(Boolean)) {
  for (const f of r.findings) {
    const v = r.verdicts.find(x => x.title === f.title)
    if (!v) { kept.push({ area: r.area, ...f, verdict: 'unverified' }); continue }
    if (v.verdict !== 'refuted') kept.push({ area: r.area, ...f, verdict: v.verdict, severity: v.severity, c_same: v.c_same, verify_reason: v.reason })
  }
}
const refuted = results.filter(Boolean).flatMap(r => r.verdicts.filter(v => v.verdict === 'refuted').map(v => ({ area: r.area, title: v.title, reason: v.reason })))
log(`${kept.length} findings kept, ${refuted.length} refuted`)

phase('Synthesize')
const report = await agent(`Write the report of a vulnerability-class audit of a Rust rewrite of curl, in Markdown.
Read ${ROOT}/HARDENING.md first for the vocabulary. Input: verified findings (JSON) below, each
with its area, verdict and severity, and the refuted ones for a short appendix.

Structure:
1. Summary: counts by severity and by pattern, and the three to five classes that matter most.
2. Findings ranked by severity then confidence, each with file:line, the failure, who reaches it,
   C same or not, and the fix. Mark every "same as C" item that is a security weakness with
   "C weakness" (the owner keeps those out of tracked files).
3. Structural changes ranked by the number of findings each closes against its cost.
4. Patterns HARDENING.md does not cover yet, if any appear more than once.
5. Appendix: refuted findings, one line each with the reason.
Do not invent findings or line numbers; use only the input. Plain words.

Findings:
${JSON.stringify(kept, null, 1)}

Refuted:
${JSON.stringify(refuted, null, 1)}`, { label: 'synthesize', phase: 'Synthesize' })

return { report, kept: kept.length, refuted: refuted.length }
