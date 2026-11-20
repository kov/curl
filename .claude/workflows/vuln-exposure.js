export const meta = {
  name: 'vuln-exposure',
  description: 'Decide, row by row, whether the Rust rewrite is affected by each report in a vulnerability inventory, then have every verdict re-read',
  whenToUse: 'Step 5 of UPSTREAM.md: args {inventory, out, ranges: [{key, rows}]}',
  phases: [
    { title: 'Read', detail: 'one reader per range of rows, read-only' },
    { title: 'Review', detail: 'one reviewer re-reads every verdict at its lines' },
  ],
}

const ROOT = '/home/kov/Projects/curl'
const { inventory, out, ranges } = args

if (!out || !out.startsWith(`${ROOT}/build/`)) throw new Error('out must be a directory under build/')

const BRIEF = `You are deciding whether a Rust rewrite of curl is affected by public curl
vulnerability reports. Write nothing but your output file: do not edit the repository, build,
run cargo, or run git commands that change state; no web access is needed.

Repo: ${ROOT}. The rewrite is in crates/ (curl-core the engine, curl-tool the command-line tool,
curl-sys-abi the C ABI shim, the rest bindings). The C tree (lib/, src/) is the reference;
upstream's fixes are in \`upstream/master\` (\`git show <sha>\`). Read CLAUDE.md first, and
DESIGN.md, ENGINE.md and HARDENING.md as needed. DIVERGENCE.md records where the rewrite differs
from C on purpose.

Inventory: ${inventory}. Each row is one public report with its upstream outcome and fixing
commit. For each row in your range decide, from the Rust code, citing file:line, one verdict:

- AFFECTED: the rewrite has the bug today. Say how it shows (inputs -> wrong behaviour).
- PORTED: the rewrite has the fix already; name the commit.
- SHIELDED-LANGUAGE: the class cannot occur in safe Rust; name the mechanism (the borrow of X,
  the bounds-checked slice in Y). Code in an unsafe module is not shielded: check it.
- SHIELDED-DESIGN: a logic bug the rewrite's structure makes impossible; name the type, owner
  or state and its file.
- NOT-APPLICABLE: the feature or backend is not in the rewrite, or upstream found no bug and the
  rewrite does what C does (say which).
- UNKNOWN: say what would decide it.

Rules:
- A verdict needs code evidence, not a fit from names. The rewrite follows C's observable
  behaviour, so logic bugs are inherited unless the design blocks them: check.
- For AFFECTED, and for open upstream issues that apply, propose the structural fix that would
  make the bug impossible (a type, an owner, a state), in one to four sentences, then the patch.
- An unfixed weakness C shares is labelled "C weakness".

Write ${out}/<key>.md, one section per row: "### <id> - <title>", then the lines Verdict,
Upstream (outcome and sha), Rust evidence (file:line and what it shows), Structural fix (or "-"),
Confidence (high, medium, low). End with a table: id | verdict | one-line reason.`

const SUMMARY = {
  type: 'object',
  properties: {
    file: { type: 'string' },
    counts: { type: 'object', additionalProperties: { type: 'integer' } },
    affected: { type: 'array', items: { type: 'string' } },
  },
  required: ['file', 'counts', 'affected'],
}

phase('Read')
const read = await parallel(ranges.map(r => () =>
  agent(`${BRIEF}\n\nYour key: ${r.key}. Your rows: ${r.rows}.`, {
    label: `read:${r.key}`, phase: 'Read', schema: SUMMARY,
  })))
const done = read.filter(Boolean)
const missing = ranges.filter((r, i) => !read[i]).map(r => r.key)
if (missing.length) log(`no verdicts for: ${missing.join(', ')}`)

phase('Review')
const review = await agent(`You are reviewing other readers' verdicts on whether a Rust rewrite
of curl is affected by public vulnerability reports. Read-only, as they were.

${BRIEF.split('Rules:')[0]}
Their files: ${done.map(d => d.file).join(', ')}.
Ranges with no verdicts: ${missing.join(', ') || 'none'}.

Re-read every AFFECTED, SHIELDED-* and UNKNOWN verdict at its cited lines, and sample the rest.
For each, say confirmed, changed (to what, and why), or refuted. A claim about the merge or the
C tree is checked against git (a test "lost" may have been merged into another upstream). Judge
each proposed structural fix: does it make the class impossible, or only this instance? Name the
patterns that recur across rows. Write ${out}/REVIEW.md: the corrected verdict table for every
row, the counts per verdict, the affected list with the fix each needs, and the recurring
patterns. Your final message: the counts and the affected list.`, { label: 'review', phase: 'Review' })

return { readers: done, missing, review }
