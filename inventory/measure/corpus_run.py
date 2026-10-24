#!/usr/bin/env python3
"""
Collect a corpus of real curl command lines, and run both tools over it.

--collect: the source packages of the distribution's packages that depend
on, recommend or suggest the curl tool, or build with it, and every small
golang-, node-, python- and ruby- source package (which keep their
upstream trees whole), are fetched with `apt-get source`
(deb-src enabled) into build/corpus, and every invocation of the tool in
their shell scripts, Dockerfiles, CI configurations, makefiles and
documentation is written to inventory/corpus_lines.json, with its package,
version, file and line. inventory/gen/corpus.py ranks them.

--diff: each distinct invocation is run by the C tool (build/c) and the
Rust tool (build/target, built with debug-hooks as the C one is a debug
build) with no transfer: `--proto =file` closes each operation, in an empty
directory, with an empty standard input and an empty HOME. Their exit
codes, standard output and standard error are compared, and the
differences, grouped, are written to inventory/corpus_diff.{json,md}.

This is a measurement, not a derivation from source: inventory/gen/all.py
does not run it.
"""

import argparse
import collections
import concurrent.futures
import datetime
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gen"))
import common
import corpus
from common import ROOT, check, md_table

BUILD = ROOT / "build" / "corpus"
LINES = common.INVENTORY / "corpus_lines.json"
# Source packages larger than this are data, not scripts.
MAX_SOURCE = 64 * 1024 * 1024
# Files larger than this are not read.
MAX_FILE = 2 * 1024 * 1024
DOCKERFILE = re.compile(r"(^|/)(Dockerfile|Containerfile)[^/]*$|\.dockerfile$", re.IGNORECASE)
CI = re.compile(r"(^|/)(\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.yml|\.travis\.yml|"
                r"Jenkinsfile|\.circleci/config\.yml|azure-pipelines\.yml|appveyor\.yml|"
                r"\.drone\.yml|\.cirrus\.yml|\.woodpecker\.yml|\.buildkite/[^/]+\.ya?ml)$")
MAKEFILE = re.compile(r"(^|/)(GNUmakefile|[Mm]akefile(\.(am|in))?|[^/]+\.mk)$")
DOC = re.compile(r"\.(md|markdown|rst|txt|adoc|asciidoc|html?|1|8)$|(^|/)README[^/]*$|"
                 r"(^|/)INSTALL[^/]*$", re.IGNORECASE)
SHELL_EXT = re.compile(r"\.(sh|bash|zsh|ksh|bats)$")
SHEBANG = re.compile(rb"^#!\s*\S*(/|env\s+)(ba|da|z|k|a)?sh\b")


def sh(args, **kw):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kw).stdout


# The source packages that keep an upstream tree whole, with its
# makefiles, Dockerfiles and CI configurations: those named so, smaller
# than SAMPLE_MAX (every SAMPLE_STEP-th of them).
SAMPLE_PREFIXES = ("golang-", "node-", "python-", "ruby-")
SAMPLE_STEP = 1
SAMPLE_MAX = 5 * 1024 * 1024


def source_index():
    """
    Return the distribution's source packages from apt's Sources indexes:
    {source: (bytes, build dependencies)}."""
    index = {}
    for f in sorted(pathlib.Path("/var/lib/apt/lists").glob("*_dists_noble_*_Sources.lz4")):
        text = subprocess.run(["lz4", "-dc", str(f)], check=True,
                              capture_output=True).stdout.decode("utf-8", "replace")
        for stanza in text.split("\n\n"):
            m = re.search(r"^Package: (\S+)", stanza, re.MULTILINE)
            if not m:
                continue
            deps = " ".join(re.findall(r"^Build-Depends(?:-Indep|-Arch)?: (.*(?:\n .*)*)",
                                       stanza, re.MULTILINE))
            size = sum(int(x) for x in re.findall(
                r"^ [0-9a-f]{32} (\d+) ", stanza.split("Checksums-")[0], re.MULTILINE))
            index[m.group(1)] = (size, deps)
    check(len(index) > 10000, f"few source packages indexed: {len(index)}")
    return index


def sources():
    """
    Return the source packages to read, each with why it was taken: the
    packages behind every binary using the curl tool, those that build
    with it, and the sample of upstream trees. {source: {"why": ...,
    "binaries": [...]}}."""
    chosen = {}
    for source, binaries in users().items():
        chosen[source] = {"why": "uses curl", "binaries": binaries}
    index = source_index()
    for source, (_, deps) in sorted(index.items()):
        if source not in chosen and re.search(r"(^|[ ,(|])curl([ ,(:|]|$)", deps):
            chosen[source] = {"why": "builds with curl", "binaries": []}
    for prefix in SAMPLE_PREFIXES:
        named = sorted(s for s, (size, _) in index.items()
                       if s.startswith(prefix) and size < SAMPLE_MAX)
        for source in named[::SAMPLE_STEP]:
            chosen.setdefault(source, {"why": f"upstream tree, {prefix}*", "binaries": []})
    return dict(sorted(chosen.items()))


def users():
    """
    Return the source packages behind every package using the curl tool:
    {source: [binary, ...]}."""
    out = sh(["apt-cache", "rdepends", "curl"])
    binaries = sorted({re.sub(r"^\s*\|?\s*", "", l) for l in out.splitlines()[2:]
                       if l.strip()})
    check(len(binaries) > 50, f"few packages use curl: {len(binaries)}")
    by_source = collections.defaultdict(list)
    for b in binaries:
        show = subprocess.run(["apt-cache", "show", b], check=False, capture_output=True,
                              text=True).stdout
        if not show:
            continue
        first = show.split("\n\n")[0]
        m = re.search(r"^Source: (\S+)", first, re.MULTILINE)
        by_source[m.group(1) if m else b].append(b)
    return dict(sorted(by_source.items()))


def fetch(source):
    """
    Fetch and unpack `source`: (version, its directory), or (version,
    None) when it is too large or cannot be fetched."""
    show = sh(["apt-cache", "showsrc", "--only-source", source])
    stanza = show.split("\n\n")[0]
    version = re.search(r"^Version: (\S+)", stanza, re.MULTILINE).group(1)
    size = sum(int(m.group(1)) for m in
               re.finditer(r"^ [0-9a-f]{32} (\d+) ", stanza.split("Checksums-")[0], re.MULTILINE))
    if size > MAX_SOURCE:
        return version, None, f"{size} bytes"
    dest = BUILD / "src" / f"{source}_{version}"
    if dest.exists():
        return version, dest, None
    dl = BUILD / "dl" / source
    dl.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["apt-get", "source", "--download-only", "-q", f"{source}={version}"],
                       check=False,
                       cwd=dl, capture_output=True, text=True)
    if r.returncode:
        return version, None, "apt-get source failed"
    dsc = next(dl.glob("*.dsc"))
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["dpkg-source", "--no-check", "--no-copy", "-x", dsc.name, str(dest)],
                       check=False,
                       cwd=dl, capture_output=True, text=True)
    if r.returncode:
        return version, None, "dpkg-source failed"
    return version, dest, None


def kind_of(rel, head):
    if DOCKERFILE.search(rel):
        return "dockerfile"
    if CI.search(rel):
        return "ci"
    if MAKEFILE.search(rel):
        return "makefile"
    if SHELL_EXT.search(rel) or SHEBANG.match(head) or rel.startswith("debian/") and \
            re.search(r"(^|/)(postinst|preinst|postrm|prerm|config|rules)$", rel):
        return "shell"
    if DOC.search(rel):
        return "doc"
    return None


# What may come before a command at the start of a line, by kind.
PREFIX = {
    "dockerfile": re.compile(r"^\s*(RUN|CMD|ENTRYPOINT|HEALTHCHECK(\s+--\S+)*\s+CMD)\s+", re.IGNORECASE),
    "ci": re.compile(r"^\s*(-\s+)?((run|script|command|cmd|before_script|after_script|"
                     r"install|test|sh|bash)\s*:\s*)?[|>]?\s*"),
    "makefile": re.compile(r"^\t[@+-]*\s*"),
    "doc": re.compile(r"^\s*(\$|#|%|>|PS>|\w*@[\w.-]+:[^$#]*[$#])\s+"),
}


def logical_lines(text):
    """Lines with backslash continuations joined: (first line number, text)."""
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        start = i
        cur = lines[i]
        while cur.endswith("\\") and i + 1 < len(lines):
            i += 1
            cur = cur[:-1] + " " + lines[i].lstrip()
        yield start + 1, cur
        i += 1


def plausible(text):
    """
    Tell whether a documentation line is a command, not prose: it has an
    option or something like a URL after `curl`."""
    try:
        argv = [corpus.word_value(w) for w in corpus.words(text)[1:]]
    except (corpus.LexError, ValueError):
        return False
    return any(a.startswith("-") or "://" in a or "$" in a or "." in a for a in argv)


def scan(path, rel):
    try:
        data = path.read_bytes()
    except OSError:
        return
    if b"\0" in data[:8192] or b"curl" not in data:
        return
    kind = kind_of(rel, data[:128])
    if kind is None:
        return
    text = data.decode("utf-8", "replace")
    for number, line in logical_lines(text):
        if "curl" not in line:
            continue
        if kind == "makefile":
            if not line.startswith("\t"):
                continue
            line = line.replace("$$", "$")
        # The exec form of a Dockerfile command: a JSON list of words.
        m = re.match(r'^\s*(RUN|CMD|ENTRYPOINT)\s+(\[.*\])\s*$', line) \
            if kind == "dockerfile" else None
        if m:
            try:
                argv = json.loads(m.group(2))
                line = " ".join("'" + a.replace("'", "'\\''") + "'" for a in argv)
            except (ValueError, TypeError, AttributeError):
                continue
        prefix = PREFIX.get(kind)
        body = prefix.sub("", line, count=1) if prefix else line
        for start, end in corpus.invocations(body):
            cut = body[start:end]
            if kind in ("doc", "ci") and not plausible(cut):
                continue
            yield {"kind": kind, "line": number, "path": rel, "text": cut}


def collect():
    by_source = sources()
    packages, skipped, lines = [], [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        fetched = dict(zip(by_source, pool.map(fetch, by_source)))
    for source, taken in by_source.items():
        version, dest, why = fetched[source]
        if dest is None:
            skipped.append({"source": source, "version": version, "why": why})
            continue
        found = []
        for path in sorted(dest.rglob("*")):
            if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_FILE:
                continue
            rel = str(path.relative_to(dest))
            if rel.startswith(".pc/"):
                continue
            found.extend({"package": source, "version": version, **rec}
                         for rec in scan(path, rel))
        # One record per place: a line the patches left twice counts once.
        seen = set()
        for rec in found:
            key = (rec["path"], rec["line"], rec["text"])
            if key not in seen:
                seen.add(key)
                lines.append(rec)
        packages.append({"source": source, "version": version, "why": taken["why"],
                         "binaries": taken["binaries"], "invocations": len(seen)})
    os_release = dict(re.findall(r'^(\w+)="?([^"\n]*)"?', pathlib.Path(
        "/etc/os-release").read_text(), re.MULTILINE))
    doc = {
        "generated-by": "inventory/measure/corpus_run.py --collect",
        "distribution": os_release.get("PRETTY_NAME", "unknown"),
        "collected": datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
        "packages": packages,
        "skipped": skipped,
        "lines": sorted(lines, key=lambda r: (r["package"], r["path"], r["line"], r["text"])),
    }
    check(len(lines) > 500, f"few invocations found: {len(lines)}")
    LINES.write_text(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
    print(f"{len(lines)} invocations from {len(packages)} sources, {len(skipped)} skipped")


C_TOOL = ROOT / "build" / "c" / "src" / "curl"
RUST_TOOL = ROOT / "build" / "target" / "debug" / "curl"
DIFF = "corpus_diff"
# An expansion stands for one word: a URL where its name says it is one.
URLISH = re.compile(r"URL|URI|HOST|LINK|SITE|ENDPOINT|SERVER|MIRROR|REPO|ADDR|API", re.IGNORECASE)
# Only file: allowed, and taken for a URL without a scheme, so nothing is
# looked up or connected to: no line names a local file to read.
GUARD = ["--proto", "=file", "--proto-default", "file"]
TIMEOUT = 20


def runnable(text):
    """
    Return the invocation's arguments to run, each expansion made one word, or
    None when it cannot be split."""
    try:
        raws = corpus.words(text)[1:]
    except (corpus.LexError, ValueError):
        return None
    argv = []
    for raw in raws:
        parts = corpus.word_parts(raw)
        value = ""
        for text_, expanded, _ in parts:
            if not expanded:
                value += text_
            elif URLISH.search(text_) and not value:
                value += "http://example.invalid/"
            else:
                value += "x"
        argv.append(value)
    # No transfer: each operation ends allowing only file:, so the
    # transfer is refused before any lookup or connection. Past a `--`
    # every word is a URL, so the guard goes before it.
    out, guarded = [], False
    for a in argv:
        if a in ("--next", "-:") and not guarded:
            out += GUARD
        if a == "--" and not guarded:
            out += GUARD
            guarded = True
        if a in ("--next", "-:"):
            guarded = False
        out.append(a)
    return out if guarded else out + GUARD


def run(tool, argv):
    with tempfile.TemporaryDirectory(prefix="corpus-") as tmp:
        home = pathlib.Path(tmp) / "home"
        cwd = pathlib.Path(tmp) / "cwd"
        home.mkdir()
        cwd.mkdir()
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home),
               "LC_ALL": "C.UTF-8", "TERM": "dumb"}
        try:
            r = subprocess.run([str(tool), *argv], check=False, cwd=cwd, env=env,
                               stdin=subprocess.DEVNULL,
                               capture_output=True, timeout=TIMEOUT)
            out = (r.returncode, r.stdout, r.stderr)
        except subprocess.TimeoutExpired:
            out = ("timeout", b"", b"")
        files = sorted(str(p.relative_to(cwd)) for p in cwd.rglob("*"))
    norm = lambda b: b.decode("utf-8", "replace").replace(tmp, "<DIR>")
    return {"exit": out[0], "stdout": norm(out[1]), "stderr": norm(out[2]), "files": files}


def run_both(argv):
    return argv, run(C_TOOL, argv), run(RUST_TOOL, argv)


def signature(c, r):
    """
    Return what a difference is, to group by: the exits, and the first lines
    of standard error that differ."""
    cl, rl = c["stderr"].splitlines(), r["stderr"].splitlines()
    first = next(((a, b) for a, b in zip(cl + [""] * len(rl), rl + [""] * len(cl)) if a != b),
                 None)
    # Numbers vary between runs and lines alike; a group is their shape.
    shape = lambda s: re.sub(r"\d+", "N", s)[:160]
    what = []
    if c["exit"] != r["exit"]:
        what.append("exit")
    if c["stdout"] != r["stdout"]:
        what.append("stdout")
    if first:
        what.append("stderr")
    if c["files"] != r["files"]:
        what.append("files")
    return (str(c["exit"]), str(r["exit"]), "+".join(what),
            shape(first[0]) if first else "", shape(first[1]) if first else "")


def diff():
    for tool in (C_TOOL, RUST_TOOL):
        check(tool.exists(), f"{tool} is not built")
    lines = json.loads(LINES.read_text())["lines"]
    by_argv = collections.defaultdict(list)
    unrunnable = 0
    for rec in lines:
        argv = runnable(rec["text"])
        if argv is None:
            unrunnable += 1
            continue
        by_argv[tuple(argv)].append(rec)
    groups = collections.defaultdict(list)
    same = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
        for argv, c, r in pool.map(run_both, sorted(by_argv)):
            if (c["exit"], c["stdout"], c["stderr"], c["files"]) == \
                    (r["exit"], r["stdout"], r["stderr"], r["files"]):
                same += 1
                continue
            groups[signature(c, r)].append({"argv": list(argv), "c": c, "rust": r,
                                            "sources": by_argv[argv]})
    # Positive control: most lines a tool accepts it accepts the same.
    check(same > 0, "no invocation behaved the same on both tools")
    ranked = sorted(groups.items(),
                    key=lambda kv: (-sum(len(x["sources"]) for x in kv[1]), kv[0]))
    data = {
        "invocations": len(lines),
        "distinct": len(by_argv),
        "unrunnable": unrunnable,
        "same": same,
        "differ": sum(len(v) for v in groups.values()),
        "groups": [{
            "c_exit": k[0], "rust_exit": k[1], "differs_in": k[2],
            "c_line": k[3], "rust_line": k[4],
            "distinct": len(v), "invocations": sum(len(x["sources"]) for x in v),
            "examples": [{"argv": x["argv"],
                          "c": x["c"], "rust": x["rust"],
                          "from": [f'{s["package"]} {s["version"]}: {s["path"]}:{s["line"]}'
                                   for s in x["sources"][:3]]}
                         for x in v[:3]],
        } for k, v in ranked],
    }
    md = ["# Both tools over the corpus\n",
          (f"{data['distinct']} distinct invocations of {data['invocations']} "
           f"({data['unrunnable']} could not be split) were run by the C tool and the Rust "
           f"tool with no transfer (`--proto =file` closing each operation). {data['same']} "
           f"behaved the same; {data['differ']} differ, in {len(data['groups'])} groups, "
           "the largest first.\n"),
          md_table(["C exit", "Rust exit", "differs in", "C's first line", "Rust's first line",
                    "distinct", "invocations"],
                   [[g["c_exit"], g["rust_exit"], g["differs_in"], g["c_line"],
                     g["rust_line"], g["distinct"], g["invocations"]]
                    for g in data["groups"]])]
    common.write(DIFF, data, "\n".join(md), ["src/tool_getparam.c"],
                 generated_by="inventory/measure/corpus_run.py --diff")
    print(f"{data['distinct']} distinct: {data['same']} same, {data['differ']} differ "
          f"in {len(data['groups'])} groups")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--collect", action="store_true")
    ap.add_argument("--diff", action="store_true")
    args = ap.parse_args()
    if args.collect:
        collect()
    if args.diff:
        diff()


if __name__ == "__main__":
    main()
