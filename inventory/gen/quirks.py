"""
Inventory the claims recorded in the C tree's prose problem lists.

Reads docs/KNOWN_BUGS.md, docs/TODO.md, docs/EXPERIMENTAL.md,
docs/DEPRECATE.md and docs/KNOWN_RISKS.md.  Each entry becomes a record
with its source path, section, title and first paragraph, tagged
`status: hypothesis` because these are claims to verify, not facts.
Writes inventory/quirks.json and inventory/quirks.md.
"""

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common
from common import check, md_table, read

DOCS = [
    "docs/KNOWN_BUGS.md",
    "docs/TODO.md",
    "docs/EXPERIMENTAL.md",
    "docs/DEPRECATE.md",
    "docs/KNOWN_RISKS.md",
]

MONTHS = ("January|February|March|April|May|June|July|August|September|"
          "October|November|December")


def first_paragraph(lines, start):
    """Return the first paragraph after line index `start` (verbatim)."""
    i = start + 1
    while i < len(lines) and not lines[i].strip():
        i += 1
    para = []
    while i < len(lines) and lines[i].strip() and not lines[i].startswith("#"):
        para.append(lines[i].rstrip())
        i += 1
    return "\n".join(para)


def section_body(lines, start):
    """Return the lines of a section after heading `start`, up to the next heading."""
    i = start + 1
    body = []
    while i < len(lines) and not lines[i].startswith("#"):
        body.append(lines[i])
        i += 1
    return body


def parse_doc(rel):
    """Split a markdown doc into section and entry records."""
    text = read(rel)
    lines = text.split("\n")
    recs = []
    section = None
    s_idx = e_idx = 0
    fenced = False
    for i, line in enumerate(lines):
        if line.startswith("```"):
            fenced = not fenced
        if fenced:
            continue
        m = re.match(r"^# (.*)$", line)
        if m:
            section = m.group(1).strip()
            s_idx += 1
            e_idx = 0
            body = section_body(lines, i)
            if any(b.strip() for b in body):
                recs.append({
                    "path": rel, "line": i + 1, "kind": "section-intro",
                    "section": section, "ordinal": f"{s_idx}",
                    "title": section, "first-paragraph": first_paragraph(lines, i),
                    "status": "hypothesis",
                })
            continue
        m = re.match(r"^## (.*)$", line)
        if m:
            check(section is not None, f"{rel}:{i + 1}: entry before any section")
            e_idx += 1
            recs.append({
                "path": rel, "line": i + 1, "kind": "entry", "section": section,
                "ordinal": f"{s_idx}.{e_idx}", "title": m.group(1).strip(),
                "heading": m.group(1).strip(),
                "first-paragraph": first_paragraph(lines, i), "status": "hypothesis",
                "_body": section_body(lines, i),
            })
    n_h2 = len(re.findall(r"^## ", text, re.MULTILINE))
    n_entries = sum(1 for r in recs if r["kind"] == "entry")
    check(n_entries == n_h2 and n_entries > 0,
          f"{rel}: entry records == '## ' headings ({n_entries}/{n_h2})")
    return recs, lines


def graduation(body):
    """Return the Graduation requirements bullet list of an EXPERIMENTAL entry."""
    out = []
    on = False
    cur = None
    for ln in body:
        if ln.startswith("Graduation requirements"):
            on = True
            continue
        if not on:
            continue
        if ln.startswith("- "):
            cur = [ln[2:].strip()]
            out.append(cur)
        elif cur is not None and ln.startswith("  ") and ln.strip():
            cur.append(ln.strip())
        elif ln.strip():
            cur = None
    return [" ".join(c) for c in out]


def deprecate_extras(recs, lines):
    """Add scheduled-removal data to DEPRECATE.md entries; parse Past removals."""
    past = []
    for r in recs:
        if r["kind"] != "entry":
            continue
        body = "\n".join(r.pop("_body"))
        if r["title"] == "Past removals":
            continue
        m = re.search(rf"(?:gets removed|removed) in ((?:{MONTHS}) \d{{4}})", body)
        a = re.search(r"release after (\d+\.\d+\.\d+)", body)
        pr = re.search(r"Pending PR: (\S+)", body)
        sentence = None
        if m:
            sentence = re.search(rf"[^.\n]*(?:gets removed|removed) in (?:{MONTHS}) \d{{4}}[^.\n]*\.?", body).group(0).strip()
        elif a:
            sentence = norm(re.search(r"In the release after.*?\.\s", body, re.DOTALL).group(0))
        r["scheduled"] = {"sentence": sentence, "removal-date": m.group(1) if m else None,
                          "after-release": a.group(1) if a else None,
                          "pending-pr": pr.group(1) if pr else None}
        check(sentence is not None, f"DEPRECATE entry '{r['title']}' has a removal schedule")
    # Past removals bullets.
    start = next(i for i, ln in enumerate(lines) if ln.strip() == "## Past removals")
    bullets = [(i + 1, ln) for i, ln in enumerate(lines[start:], start) if ln.startswith("- ")]
    for ln_no, ln in bullets:
        m = re.match(r"^- (.*) \((removed|became opt-in) in (\d+\.\d+\.\d+)\)$", ln)
        check(m is not None, f"DEPRECATE.md:{ln_no}: past-removal bullet parses: {ln!r}")
        past.append({"path": "docs/DEPRECATE.md", "line": ln_no, "kind": "past-removal",
                     "what": m.group(1), "claim-state": m.group(2), "version": m.group(3),
                     "status": "hypothesis"})
    check(len(past) == sum(1 for ln in lines if ln.startswith("- ")),
          "every DEPRECATE bullet is a past removal")
    check(any(p["what"] == "RTMP" for p in past) and any(p["what"] == "hyper" for p in past),
          "past removals include RTMP and hyper")
    return past


def norm(s):
    """Collapse whitespace."""
    return re.sub(r"\s+", " ", s).strip()


def version_tuple(v):
    """Return a numeric tuple for an x.y.z version."""
    return tuple(int(x) for x in v.split("."))


def main():
    """Generate inventory/quirks.{json,md}."""
    records = []
    counts = {}
    past = []
    for rel in DOCS:
        recs, lines = parse_doc(rel)
        if rel.endswith("DEPRECATE.md"):
            past = deprecate_extras(recs, lines)
        if rel.endswith("EXPERIMENTAL.md"):
            for r in recs:
                if r["kind"] == "entry":
                    r["graduation-requirements"] = graduation(r.pop("_body"))
        for r in recs:
            r.pop("_body", None)
        counts[rel] = {"entries": sum(1 for r in recs if r["kind"] == "entry"),
                       "section-intros": sum(1 for r in recs if r["kind"] == "section-intro")}
        records.extend(recs)

    by_title = {(r["path"], r["title"]): r for r in records if r["kind"] == "entry"}
    check(("docs/DEPRECATE.md", "drop NTLM support") in by_title, "NTLM deprecation present")
    check(by_title[("docs/KNOWN_BUGS.md", "IMAPS connection fails with Rustls error")]["section"] == "TLS",
          "Rustls IMAPS bug is in the TLS section")
    ntlm = by_title[("docs/DEPRECATE.md", "drop NTLM support")]
    check(ntlm["scheduled"]["removal-date"] == "September 2026", "NTLM removal date parsed")
    exp = [r for r in records if r["path"] == "docs/EXPERIMENTAL.md" and r["kind"] == "entry"
           and r["title"] != "Graduation"]
    check(all(r["graduation-requirements"] for r in exp),
          "every experimental feature lists graduation requirements")

    tree_version = re.search(r'#define LIBCURL_VERSION "([^"]+)"', read("include/curl/curlver.h")).group(1)
    base = re.match(r"\d+\.\d+\.\d+", tree_version).group(0)
    newest_removal = max(version_tuple(p["version"]) for p in past)
    check(newest_removal <= version_tuple(base),
          f"no past removal is newer than the tree version {tree_version}")

    data = {
        "c-tree-version": tree_version,
        "counts": counts,
        "records": sorted(records, key=lambda r: (r["path"], r["line"])),
        "past-removals": past,
        "ordinal-note": "docs/TODO.md and docs/KNOWN_BUGS.md carry no section numbers; "
                        "'ordinal' is the position of the section and entry in the file",
    }

    md = ["# Claims in the C tree's problem lists\n",
          ("Each `##` entry of the five documents below is a record in `quirks.json` with its "
          "source path and line, section, title and verbatim first paragraph. All records carry "
          "`status: hypothesis`: they are claims to verify against the tree, not facts. The "
          "documents have no section numbers, so `ordinal` is the position of the section and "
          f"entry in the file. C tree version: `{tree_version}`.\n"),
          md_table(["document", "entries", "section intros"],
                   [[k, v["entries"], v["section-intros"]] for k, v in counts.items()])]
    emit = md.append
    for rel in DOCS:
        emit(f"## {rel}\n")
        emit(md_table(["ordinal", "line", "section", "title"],
                      [[r["ordinal"], r["line"], r["section"], r["title"]]
                       for r in data["records"] if r["path"] == rel and r["kind"] == "entry"]))
    emit("## Scheduled removals (docs/DEPRECATE.md)\n")
    emit(md_table(["title", "removal date", "after release", "pending PR"],
                  [[r["title"], r["scheduled"]["removal-date"] or "-",
                    r["scheduled"]["after-release"] or "-", r["scheduled"]["pending-pr"] or "-"]
                   for r in data["records"]
                   if r["path"] == "docs/DEPRECATE.md" and "scheduled" in r]))
    emit(f"## Past removals ({len(past)})\n")
    emit(md_table(["what", "state", "version"], [[p["what"], p["claim-state"], p["version"]] for p in past]))

    common.write("quirks", data, "\n".join(md), set(DOCS) | {"include/curl/curlver.h"})


if __name__ == "__main__":
    main()
