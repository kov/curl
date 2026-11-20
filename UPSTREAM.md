# Catching up with upstream

The C tree is the reference the rewrite is scored against, and upstream keeps moving: fixes,
new tests, changed traces, new security reports. A catch-up brings the C tree to upstream's
master and the rewrite back to it, and turns the reports published since the last one into
fixes here, structural where a type can hold the invariant. It runs on the owner's request.
Its order is fixed: survey, merge, score, inventory, exposure, port, diverge, review, close.
Each step's output is an input of the next, and skipping one leaves the next working from a
guess.

Working notes go in untracked `build/` files, named for the upstream commit the catch-up merges
to: `build/UPSTREAM-MERGE-<sha10>.md` (the port list), `build/VULN-INVENTORY-<sha10>.md` (the
reports), and the analysis in `build/vuln-<sha10>/`. What outlives a catch-up is in commits,
`DIVERGENCE.md`, `HARDENING.md` and the private `build/UPSTREAM-REGISTER.md`; what it leaves
undone moves to the next catch-up's notes.

## 1. Survey

Before merging, establish what moved, with `date` run first:

- the range: the last merged upstream commit (`git log --merges --first-parent`) to
  `upstream/master` after a fetch; the number of commits, and of those touching `lib/`, `src/`
  and `include/`. A change under `include/` is an ABI change and is ported before anything else;
- CVEs published since the last catch-up (`https://curl.se/docs/vuln.json`, by `published`);
- the CI pins of the backends and libraries (`.github/workflows/`), whose new versions the
  backend oracles are rebuilt on;
- upstream decisions in `docs/DEPRECATE.md` and the changelog that change `SCOPE.md`'s claims (a
  feature removed or scheduled for removal);
- the previous catch-up's notes: its unported commits and open items start this one's port
  list;
- every revert in the range, with its public reason (the PR, the issue): a revert can undo a
  fix this tree ported, or point to the change upstream made instead.

## 2. Merge

1. Renumber the tests this tree added that collide with upstream's new numbers, in a commit of
   its own before the merge.
2. Merge `upstream/master` into the working branch. Conflicts are in the test lists
   (`tests/data/Makefile.am`, `tests/libtest/Makefile.inc`); upstream's removals win.
3. Run upstream's test linter over the tree's added tests (`cd tests && perl ./test-linter.pl
   ../build/c`) and fix what it reports.
4. Rebuild the C reference (`build/c`), then regenerate the inventory (`inventory/gen/all.py`,
   then `--check`) in a commit separate from any C-tree change: its stamp is the last commit
   that touched the C tree. Regenerate the Rust files generated from C sources (`gen/all.py`)
   in a commit of their own too; `generated_is_fresh` fails until then. Then remeasure the
   baseline (`inventory/measure/baseline.py --run`).

## 3. Score

Score the Rust leg against the new baseline (`inventory/measure/score.py`). A failure is rerun
alone before it is triaged: a pytest case can fail under the full run's load only. Every
failure is one of: a port this catch-up owes, a test of this tree's that C now fails (its expectation moves
with the port), or a regression. A test this tree added that the new C fails names a port: C's
new trace, message or order is the target. Highest-yield ports first: one shared behaviour (an
FTP `QUIT`, a feature name in `curl -V`) can recover hundreds of tests and clears the noise the
rest are triaged through.

## 4. Inventory the reports

Build `build/VULN-INVENTORY-<sha10>.md` for the window since the last catch-up. Its inclusion
rule is written at its top, so a later reader knows what absence means. It starts from the
previous inventory's still-open reports: their fixes are the likeliest security content of a
short range, and an open report's PR is read before a fix is designed for it.

- **GitHub:** every curl/curl issue labelled `vuln:*` (Table A); unlabelled issues whose report
  claims a security angle, and fuzzing crash reports, each read (Table B).
- **HackerOne:** every report on `team:curl` disclosed in the window, each one's JSON opened
  (Table C).
- **vuln.json**, the maintainer's blog and the mailing lists, for what they name.
- Each row: the report, its upstream outcome, and the fixing commit, found by searching
  `git log upstream/master` for the issue number, the report's id and its HackerOne id; a fix
  matched by topic alone is marked "probable".
- Cross-reference with the port list: a fix in the range that the port list lacks is added to
  it. Fixes before the range get a row too: whether the rewrite has them is checked, not
  assumed.
- A **limits** section: sources not reached, and what cannot be seen (an embargoed report, a
  report with no security wording that no one labelled).

## 5. Exposure

For each row, decide from the Rust code, with `file:line`, one verdict: affected; ported;
shielded by the language (the mechanism named, and never in an unsafe module); shielded by
design (the type or owner named); not applicable; or unknown, with what would decide it. An
affected row gets the structural fix that would make it impossible, not only the patch.
Upstream's "not a bug" still gets a statement of what the rewrite does.

For an inventory of more than a few dozen rows, the `vuln-exposure` workflow
(`.claude/workflows/vuln-exposure.js`, args `{inventory, out, ranges}` with `out` under
`build/`) runs readers per range of rows, read-only, then an independent reviewer that re-reads
every verdict at its lines. For a small one, one reader and one reviewer agent do the same.
Launching a workflow is the owner's call. A reader's claim is a hypothesis: the reviewer refutes
some, and so does the C tree (a test "lost" in the merge that upstream merged into another).
Publish the result to the owner as a private page: the table, the counts per verdict, the
affected list with the fixes proposed.

## 6. Port

Work the port list in the owner's order, typically: the score's highest-yield items, then
security, then behaviour.

- **C's behaviour first**, as its own commit, citing the upstream commit; a restructure that
  makes the class impossible follows as another.
- Each port carries the test that reaches it most directly (upstream's runtests case, or a Rust
  test), armed by planting the fault, and a sabotage entry where it guards an invariant.
- A test whose expectation upstream changed is updated with the port, after running the new C
  on it.
- A `DIVERGENCE.md` entry that C now matches is deleted. For every in-range fix, search
  `DIVERGENCE.md` for the C function or option it touches, and rerun the entry's own case on
  the merged C: an upstream fix of C's side falsifies the entry silently, and neither the score
  nor the exposure reader reliably finds it.
- Audit the port list once the ports run out: a reader per area of the merged range, read-only,
  listing each upstream commit under `lib/` and `src/` that is not ported, with the Rust
  `file:line` it would change. The audit finds what triage missed.

## 7. Diverge

Where a report is a weakness C keeps, the rewrite may do the safe thing (`HARDENING.md`,
"Diverging from C for security"):

- The owner decides each case, from a description of what changes for an application, and
  what real users (`WebKit`, the command-line corpus) do.
- Run the C build on the case first. The `DIVERGENCE.md` entry says what each side does,
  measured, or labelled as read from the code; it carries the test that pins it.
- No tracked text says C is weak: not the entry, a test name, a code comment, or a commit
  message. "Against the C build, X does Y" in a commit message is such a text. The weakness, its
  reproducer and its state go to `build/UPSTREAM-REGISTER.md`.
- A report to curl's security team is drafted (`build/UPSTREAM-REPORTS-DRAFT.md`, reproducers
  in `build/upstream-repro/`) and sent by the owner before the commits that diverge are
  pushed.

## 8. Review

Run the two reviews of `HARDENING.md` once the ports land:

- **What would have prevented it**, over the affected rows: the root cause, the language feature
  or design that would have made it impossible here, and the class, searched for across the
  tree.
- **The idiom audit**: the `hardening-review` workflow (`.claude/workflows/hardening-review.js`),
  a reader per area, a skeptic per area that re-reads every finding at its lines, and a
  synthesis ranking the classes and the structural changes. Over the whole tree it is some two
  dozen agents: run it whole when `HARDENING.md` gained patterns, else over the code the merge
  and the ports changed. As for the exposure workflow, launching it is the owner's call.

Each confirmed finding is re-read at its lines before it is acted on, and fixed in the order
the owner approves: patterns `HARDENING.md` lacks are added to it.

## 9. Close

- The whole-workspace check (the local, untracked `build/m4-check.sh`, on banana), which runs
  every crate's tests in every feature set: a stale expectation in a crate the port did not
  touch shows only there.
- The runtests suite as the scorer runs it (the local `build/leg.py runtests -a -n -j8 '!96'
  '!558'`;
  without `-a` it stops at the first failure, and 96 and 558 are replaced by Rust tests), and
  pytest; then the score.
- The sabotage sweep and cargo-mutants over the diff since the merge, on banana.
- The backend oracles rebuilt on the new pins, and their legs scored.
- `MILESTONES.md`, `SCOPE.md` and `README.md` brought true for what moved.
- Before a push: grep the unpushed messages and the `DIVERGENCE.md` diff for each open register
  entry's identifiers, with a positive control; the reports sent.
- What is left undone listed for the next catch-up; the rest of the `build/` notes deleted,
  their conclusions landed.

## Pitfalls

- A probe linked to the C library keeps loading it through its rpath: for the Rust leg, link
  against `build/rust/lib` or check `ldd` before believing a result.
- The command-line tool is no oracle for state a multi keeps between transfers (a CA store, a
  connection pool): it makes a handle per URL. Write the libcurl program.
- A sabotage entry whose plant sits on one of several paths to the code it guards survives the
  sweep: plant where every path passes (the shared helper, not one caller).
- An agent told to clean up after itself clears the session's scratchpad, other runs' logs
  with it. Give each agent its own directory under `build/vuln-<sha10>/` and name what it may
  delete.
- A reviewer working while ports land reviews a moving tree: tell it the commit to start from
  and that later commits are expected, so it reports verdicts per commit.
- Upstream's style checks run over this tree's markdown too (test 1275).
- A trace a test captured from C is re-captured from the new C, not edited by hand.
