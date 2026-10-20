#!/usr/bin/env python3
"""
Inventory of the curl command-line tool's externally visible surface.

Sections: option docs (docs/cmdline-opts/*.md), the option table in
src/tool_getparam.c and their cross-check, --write-out variables, exit
codes, environment variables and config-file lookup, generated files.
"""

import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import ROOT, check, frontmatter, md_table, read, write

NAME = "cli"
SOURCES = set()


def src(rel):
    SOURCES.add(rel)
    return read(rel)


def note(disc, kind, long_, detail):
    """Append one discrepancy record to `disc`."""
    disc.append({"kind": kind, "long": long_, "detail": detail})


def lineno(text, pos):
    return text.count("\n", 0, pos) + 1


def scalar(v):
    """Frontmatter scalar; an empty value parses as [] in common."""
    if isinstance(v, list):
        check(not v, f"scalar key carries a list: {v!r}")
        return ""
    return v


# --------------------------------------------------------------------------
# 1. option docs
# --------------------------------------------------------------------------

DOCDIR = "docs/cmdline-opts"
KNOWN_KEYS = {
    "c", "SPDX-License-Identifier", "Long", "Short", "Arg", "Magic", "Mutexed",
    "Requires", "Protocols", "Category", "Added", "Multi", "Scope", "Tags",
    "Experimental", "Help", "See-also", "Example",
}
LIST_KEYS = {"See-also", "Example"}  # YAML lists; the rest are scalars
KNOWN_MULTI = {"single", "boolean", "append", "mutex", "custom", "per-URL"}


def makefile_list(text, var):
    m = re.search(rf"^{var} = \\\n((?:[^\n]*\\\n)*[^\n]*)", text, re.MULTILINE)
    check(m, f"{var} not found in Makefile.inc")
    return sorted(x for x in re.split(r"[\s\\]+", m.group(1)) if x)


def parse_docs():
    mk = src(f"{DOCDIR}/Makefile.inc")
    dpages = makefile_list(mk, "DPAGES")
    support = makefile_list(mk, "SUPPORT")

    files = sorted(os.listdir(ROOT / DOCDIR))
    skipped, optfiles = [], []
    for f in files:
        if f.startswith("_") and f.endswith(".md"):
            skipped.append({"file": f, "reason": "support page (_*.md) "
                            "included into curl.1, not an option"})
        elif f == "MANPAGE.md":
            skipped.append({"file": f, "reason": "documents the .md format "
                            "itself, not an option"})
        elif f.endswith(".md"):
            optfiles.append(f)
        else:
            skipped.append({"file": f, "reason": "build file, not an option"})
    # positive controls: independent lists from Makefile.inc
    check(optfiles == dpages,
          "option .md files on disk differ from DPAGES in Makefile.inc: "
          f"{sorted(set(optfiles) ^ set(dpages))}")
    check(sorted(s["file"] for s in skipped if s["file"].startswith("_"))
          == support, "_*.md files differ from SUPPORT in Makefile.inc")

    opts, keycount, unknown = [], {}, {}
    for f in optfiles:
        SOURCES.add(f"{DOCDIR}/{f}")
        meta, _body = frontmatter(read(f"{DOCDIR}/{f}"))
        for k in meta:
            keycount[k] = keycount.get(k, 0) + 1
            if k not in KNOWN_KEYS:
                unknown.setdefault(k, []).append(f)
        for k in LIST_KEYS:
            if k in meta:
                check(isinstance(meta[k], list), f"{f}: {k} is not a list")
        long_ = scalar(meta.get("Long", ""))
        check(long_, f"{f}: no Long")
        o = {
            "file": f,
            "long": long_,
            "short": scalar(meta.get("Short", "")) or None,
            "arg": scalar(meta.get("Arg", "")) or None,
            "magic": scalar(meta.get("Magic", "")) or None,
            "help": scalar(meta.get("Help", "")),
            "added": scalar(meta.get("Added", "")),
            "multi": scalar(meta.get("Multi", "")),
            "scope": scalar(meta.get("Scope", "")) or None,
            "experimental": scalar(meta.get("Experimental", "")) or None,
            "category": scalar(meta.get("Category", "")).split(),
            "protocols": scalar(meta.get("Protocols", "")).split(),
            "requires": scalar(meta.get("Requires", "")).split(),
            "mutexed": scalar(meta.get("Mutexed", "")).split(),
            "tags": scalar(meta.get("Tags", "")).split(),
            "see_also": sorted(meta.get("See-also", [])),
            "examples": list(meta.get("Example", [])),
            # keys exactly as present, so no key can be lost by normalising
            "keys_present": sorted(meta),
        }
        for k, ufiles in unknown.items():
            if f in ufiles:
                o.setdefault("unknown_keys", {})[k] = meta[k]
        opts.append(o)

    # doc-internal consistency
    disc = []
    longs = {}
    for o in opts:
        if o["file"] != o["long"] + ".md":
            note(disc, "doc-filename-vs-Long", o["long"], o["file"])
        if o["long"] in longs:
            note(disc, "doc-duplicate-Long", o["long"], o["file"])
        longs[o["long"]] = o
        if o["multi"] not in KNOWN_MULTI:
            note(disc, "doc-unknown-Multi", o["long"], o["multi"])
    shorts = {}
    for o in opts:
        if o["short"]:
            if o["short"] in shorts:
                note(disc, "doc-duplicate-Short", o["long"], f"{o['short']} also {shorts[o['short']]}")
            shorts[o["short"]] = o["long"]
    for o in opts:
        for k in ("mutexed", "see_also"):
            for ref in o[k]:
                if ref not in longs:
                    note(disc, f"doc-dangling-{k}", o["long"], ref)
    return opts, skipped, keycount, unknown, disc, dpages


# --------------------------------------------------------------------------
# generic scanner: regex entries inside a C block with #if tracking
# --------------------------------------------------------------------------

PP = re.compile(r"^[ \t]*#[ \t]*(?P<d>if|ifdef|ifndef|else|elif|endif)\b"
                r"(?P<c>[^\n]*)$", re.MULTILINE)


def scan(block, entry_re, base_line=1):
    """
    Return (match, guard, line) for each entry match.

    `guard` is the conjunction of the enclosing preprocessor conditions.
    """
    events = [(m.start(), "pp", m) for m in PP.finditer(block)]
    events += [(m.start(), "entry", m)
               for m in re.finditer(entry_re, block, re.DOTALL)]
    events.sort(key=lambda e: e[0])
    stack, out = [], []
    for pos, kind, m in events:
        if kind == "entry":
            out.append((m, " && ".join(c for c in stack if c),
                        base_line + block.count("\n", 0, pos)))
            continue
        d, c = m.group("d"), re.sub(r"/\*.*?\*/", "", m.group("c")).strip()
        if d == "if":
            stack.append(c)
        elif d == "ifdef":
            stack.append(f"defined({c})")
        elif d == "ifndef":
            stack.append(f"!defined({c})")
        elif d == "else":
            stack[-1] = f"!({stack[-1]})"
        elif d == "elif":
            stack[-1] = f"!({stack[-1]}) && {c}"
        elif d == "endif":
            stack.pop()
    check(not stack, "unbalanced preprocessor conditionals in scanned block")
    return out


# --------------------------------------------------------------------------
# 2. option table
# --------------------------------------------------------------------------

def parse_table():
    hdr = src("src/tool_getparam.h")
    c = src("src/tool_getparam.c")

    flagvals = {m.group(1): int(m.group(2), 0) for m in
                re.finditer(r"^#define (ARG_[A-Z]+)\s+(0x[0-9a-fA-F]+|\d+)", hdr, re.MULTILINE)}
    typemask = flagvals.pop("ARG_TYPEMASK")
    types = {v: k for k, v in flagvals.items() if v <= typemask}
    flags = {k: v for k, v in flagvals.items() if v > typemask}
    check(set(types.values()) == {"ARG_NONE", "ARG_BOOL", "ARG_STRG",
                                  "ARG_FILE", "ARG_SECS", "ARG_UNUM"},
          f"unexpected ARG types {types}")
    check(set(flags) == {"ARG_DEPR", "ARG_CLEAR", "ARG_TLS", "ARG_NO"},
          f"unexpected ARG flags {flags}")

    # cmdline_t enum
    m = re.search(r"typedef enum \{\n(.*?)\n\} cmdline_t;", hdr, re.DOTALL)
    check(m, "cmdline_t enum not found")
    enum = re.findall(r"^\s*(C_[A-Z0-9_]+)\s*,?\s*$", m.group(1), re.MULTILINE)
    check(len(enum) == len(set(enum)), "duplicate cmdline_t enumerator")

    start = c.index("static const struct LongShort aliases[] = {")
    end = c.index("\n};", start)
    block = c[start:end]
    base = lineno(c, start)
    entry_re = (r"\{\s*\"(?P<name>[^\"]+)\"\s*,\s*(?P<flags>[A-Z_|\s]+?)\s*,"
                r"\s*'(?P<letter>.)'\s*,\s*(?P<cmd>C_[A-Z0-9_]+)\s*\}")
    found = scan(block, entry_re, base)
    # positive controls: two independent counts of entries
    nbrace = block.count('{"')
    check(len(found) == nbrace,
          f"table entries parsed {len(found)} != brace-quote count {nbrace}")
    check(len(found) == len(re.findall(r"C_[A-Z0-9_]+\},", block)),
          "table entries parsed != count of 'C_x},' terminators")

    entries = []
    for m, guard, line in found:
        toks = [t.strip() for t in m.group("flags").split("|")]
        ty = [t for t in toks if t in types.values()]
        check(len(ty) == 1, f"{m.group('name')}: need exactly one ARG type")
        fl = sorted(t for t in toks if t in flags)
        check(sorted(ty + fl) == sorted(toks), f"{m.group('name')}: bad flags")
        entries.append({
            "long": m.group("name"),
            "type": ty[0],
            "flags": fl,
            "short": None if m.group("letter") == " " else m.group("letter"),
            "cmd": m.group("cmd"),
            "guard": guard or None,
            "line": line,
            "file": "src/tool_getparam.c",
        })
    names = [e["long"] for e in entries]
    check(len(names) == len(set(names)), "duplicate long name in table")
    cmds = [e["cmd"] for e in entries]
    check(len(cmds) == len(set(cmds)), "duplicate C_ id in table")
    unsorted = [(a, b) for a, b in zip(names, names[1:]) if not a < b]
    maxlen = max(len(n) for n in names)

    disc = []
    for a, b in unsorted:
        note(disc, "table-not-strcmp-sorted", b, f"follows {a}")
    shorts = {}
    for e in entries:
        if e["short"]:
            if e["short"] in shorts:
                note(disc, "table-duplicate-short", e["long"], e["short"])
            shorts[e["short"]] = e["long"]
    for e in entries:
        exp = "C_" + re.sub(r"[-.]", "_", e["long"]).upper()
        if e["cmd"] != exp:
            note(disc, "table-cmd-name-not-derived-from-long", e["long"],
                 f"{e['cmd']} (derived would be {exp})")
    tabcmd = set(cmds)
    for cid in sorted(set(enum) - tabcmd):
        note(disc, "enum-id-without-table-entry", None, cid)
    for cid in sorted(tabcmd - set(enum)):
        note(disc, "table-id-not-in-enum", None, cid)
    check(entries and enum, "empty table or enum")
    return {
        "arg_types": types, "arg_flags": flags,
        "entries": sorted(entries, key=lambda e: e["long"]),
        "enum_count": len(enum),
        "max_long_name_len": maxlen,
        "max_option_len_in_getparameter": int(
            re.search(r"#define MAX_OPTION_LEN (\d+)", c).group(1)),
    }, disc


# --------------------------------------------------------------------------
# cross-check docs vs table
# --------------------------------------------------------------------------

def crosscheck(opts, table):
    tab = {e["long"]: e for e in table["entries"]}
    disc, pairs, used = [], [], set()
    for o in opts:
        L = o["long"]
        via = None
        if L in tab:
            via, t = "direct", tab[L]
        elif L.startswith("no-") and L[3:] in tab:
            via, t = "no-prefix", tab[L[3:]]
        else:
            note(disc, "doc-option-not-in-table", L, o["file"])
            continue
        used.add(t["long"])
        pairs.append({"doc": L, "table": t["long"], "via": via})
        if via == "no-prefix" and "ARG_NO" not in t["flags"]:
            note(disc, "doc-no-prefix-but-table-lacks-ARG_NO", L, f"table {t['long']} {t['flags']}")
        if via == "direct" and "ARG_NO" in t["flags"]:
            note(disc, "table-ARG_NO-but-doc-lacks-no-prefix", L, "")
        if o["short"] != t["short"]:
            note(disc, "short-letter-differs", L, f"doc {o['short']!r} table {t['short']!r}")
        takes_arg = t["type"] in ("ARG_STRG", "ARG_FILE", "ARG_SECS", "ARG_UNUM")
        if bool(o["arg"]) != takes_arg:
            note(disc, "arg-presence-differs", L, f"doc Arg {o['arg']!r} table {t['type']}")
        is_bool = t["type"] == "ARG_BOOL"
        if (o["multi"] == "boolean") != is_bool:
            note(disc, "boolean-differs", L, f"doc Multi {o['multi']} table {t['type']}")
        if ("deprecated" in o["category"]) != ("ARG_DEPR" in t["flags"]):
            note(disc, "deprecated-differs", L, f"doc Category {o['category']} table "
                                   f"{t['flags']}")
        needs_tls = "TLS" in o["requires"]
        if needs_tls != ("ARG_TLS" in t["flags"]):
            note(disc, "tls-flag-vs-Requires-TLS", L, f"doc Requires {o['requires']} table "
                                   f"{t['flags']}")
        if o["magic"] and t["type"] != "ARG_NONE":
            note(disc, "magic-option-not-ARG_NONE", L, f"Magic {o['magic']} table {t['type']}")
    for e in table["entries"]:
        if e["long"] not in used:
            g = e["guard"] or ""
            kind = ("table-only-debug-or-platform"
                    if re.search(r"DEBUGBUILD|WATT32", g)
                    else "table-option-not-in-docs")
            note(disc, kind, e["long"], g)
    return pairs, disc


# --------------------------------------------------------------------------
# 3. --write-out
# --------------------------------------------------------------------------

def parse_writeout():
    c = src("src/tool_writeout.c")
    h = src("src/tool_writeout.h")
    doc = src(f"{DOCDIR}/write-out.md")

    m = re.search(r"typedef enum \{\n(.*?)\n\} writeoutid;", h, re.DOTALL)
    check(m, "writeoutid enum not found")
    ids = re.findall(r"^\s*(VAR_[A-Z0-9_]+)\s*,?", m.group(1), re.MULTILINE)

    start = c.index("static const struct writeoutvar variables[] = {")
    end = c.index("\n};", start)
    block = c[start:end]
    base = lineno(c, start)
    ent_re = (r"\{\s*\"(?P<name>[^\"]+)\"\s*,\s*(?P<id>VAR_\w+)\s*,\s*"
              r"(?P<ci>CURLINFO_\w+)\s*,\s*(?P<fn>\w+)\s*\}")
    found = scan(block, ent_re, base)
    check(len(found) == block.count('{ "'),
          "write-out entries parsed != '{ \"' count")
    # doc headings: variables are '## `name`' up to the '##' divider
    head, _, tail = doc.partition("\n##\n")
    check(tail, "write-out.md time-format divider not found")
    docvars = re.findall(r"^## `([^`]+)`$", head, re.MULTILINE)
    timefmt = re.findall(r"^## `(%[^`]+)`$", tail, re.MULTILINE)
    # positive control: total '## ' headings = variables + time formats
    check(len(re.findall(r"^## ", doc, re.MULTILINE)) == len(docvars) + len(timefmt),
          "write-out.md has '## ' headings outside the two lists")
    check(len(timefmt) > 20, "time conversion specifiers not parsed")

    # per-variable doc text
    sections = {}
    for m2 in re.finditer(r"^## `([^`]+)`\n(.*?)(?=^## |\Z)", head, re.MULTILINE | re.DOTALL):
        sections[m2.group(1)] = " ".join(m2.group(2).split())

    fn_kind = {"writeString": "string", "writeLong": "long",
               "writeOffset": "curl_off_t", "writeTime": "time-us",
               "NULL": "special"}
    entries = []
    for m2, guard, line in found:
        name, vid, ci, fn = (m2.group(k) for k in ("name", "id", "ci", "fn"))
        check(vid in ids, f"{name}: {vid} not in enum")
        reads = None
        if ci == "CURLINFO_NONE":
            bodies = []
            for cm in re.finditer(rf"case {vid}:\s*\n((?:\s*case \w+:\s*\n)*)"
                                  r"(.*?)\bbreak;", c, re.DOTALL):
                b = " ".join(cm.group(2).split())
                if b and b not in bodies:
                    bodies.append(b)
            reads = " ;; ".join(bodies) or None
        sec = sections.get(name)
        added = re.search(r"[Aa]dded in (?:curl )?([0-9.]+[0-9])", sec or "")
        entries.append({
            "name": name, "id": vid, "curlinfo": None if ci == "CURLINFO_NONE" else ci,
            "writefunc": fn if fn != "NULL" else None,
            "type": fn_kind.get(fn, fn),
            "json_member": fn != "NULL",
            "reads_source": reads, "line": line, "guard": guard or None,
            "in_docs": name in docvars,
            "doc_added": added.group(1) if added else None,
            "doc_text": sec,
        })
    names = [e["name"] for e in entries]
    check(names == sorted(names), "write-out table not strcmp-sorted "
          "(bsearch would fail)")
    check(len(names) == len(set(names)), "duplicate write-out name")

    # special %name{arg} forms handled by the parser
    specials = []
    for pref in ("header", "time", "output"):
        lit = re.search(rf'"{pref}\{{"', c)
        check(lit, f"parser form {pref}{{ not found in tool_writeout.c")
        specials.append({"form": f"%{pref}{{...}}", "line": lineno(c, lit.start()),
                         "in_docs": any(d.startswith(pref + "{") for d in docvars)})
    disc = []
    docnames = {d for d in docvars if "{" not in d}
    for d in sorted(docnames - set(names)):
        note(disc, "writeout-doc-var-not-in-table", d, "")
    for n in sorted(set(names) - docnames):
        note(disc, "writeout-table-var-not-in-docs", n, "")
    for s in specials:
        if not s["in_docs"]:
            note(disc, "writeout-special-form-not-in-docs", s["form"], "")
    for d in docvars:
        if "{" in d and d.split("{")[0] not in ("header", "output", "time"):
            note(disc, "writeout-unknown-doc-special", d, "")
    used_ids = {e["id"] for e in entries}
    for i in ids:
        if i not in used_ids and i not in ("VAR_NONE", "VAR_NUM_OF_VARS"):
            note(disc, "writeout-enum-id-without-table-entry", i, "")
    # positive controls
    byname = {e["name"]: e for e in entries}
    check(byname["http_code"]["curlinfo"] == "CURLINFO_RESPONSE_CODE"
          and byname["response_code"]["id"] == byname["http_code"]["id"],
          "write-out http_code/response_code control failed")
    check(byname["time_total"]["type"] == "time-us"
          and byname["exitcode"]["reads_source"], "write-out control failed")
    return {
        "variables": entries, "special_forms": specials,
        "time_format_specifiers": timefmt,
        "doc_headings": docvars,
        "escapes_in_format": sorted(set(re.findall(
            r"case '([rnt])':", c[c.index("else if('\\\\' == *ptr"):]))),
    }, disc


# --------------------------------------------------------------------------
# 4. exit codes
# --------------------------------------------------------------------------

def parse_exitcodes():
    doc = src(f"{DOCDIR}/_EXITCODES.md")
    codes = [{"code": m.group(1), "text": " ".join(m.group(2).split())}
             for m in re.finditer(r"^## (\S+)\n(.*?)(?=^## |\Z)", doc,
                                  re.MULTILINE | re.DOTALL)]
    check(len(codes) == len(re.findall(r"^## ", doc, re.MULTILINE)),
          "exit code headings not all parsed")
    numeric = [int(c["code"]) for c in codes if c["code"].isdigit()]
    check(numeric == sorted(set(numeric)), "doc exit codes not strictly ascending")

    h = src("include/curl/curl.h")
    s = h.index("  CURLE_OK = 0,")
    e = h.index("  CURL_LAST /* never use! */", s)
    enum, n = [], -1
    for line in h[s:e].splitlines():
        m = re.match(r"\s*(CURLE_\w+)(?:\s*=\s*(\d+))?\s*,\s*(?:/\*\s*(\d+)\b)?", line)
        if not m:
            continue
        n = int(m.group(2)) if m.group(2) else n + 1
        if m.group(3) is not None:
            check(int(m.group(3)) == n or m.group(2) is None and False,
                  f"{m.group(1)}: counted {n} but comment says {m.group(3)}")
        enum.append({"name": m.group(1), "value": n,
                     "obsolete": "OBSOLETE" in m.group(1)})
    values = [x["value"] for x in enum]
    check(values == list(range(len(values))), "CURLcode values not dense")
    check(enum[0]["name"] == "CURLE_OK" and
          next(x for x in enum if x["value"] == 28)["name"]
          == "CURLE_OPERATION_TIMEDOUT",
          "CURLcode positive control failed (28 = OPERATION_TIMEDOUT)")

    byval = {x["value"]: x["name"] for x in enum}
    disc = []
    for c in codes:
        if c["code"].isdigit():
            c["curle"] = byval.get(int(c["code"]))
            if c["curle"] is None:
                note(disc, "exit-code-doc-not-in-CURLcode", c["code"], "")
    doc_nums = set(numeric)
    for x in enum:
        if x["value"] not in doc_nums:
            note(disc, "CURLcode-not-in-exit-code-docs"
                         + ("-obsolete" if x["obsolete"] else ""), str(x["value"]), x["name"])

    # ParameterError -> exit code, from operate()
    op = src("src/tool_operate.c")
    s2 = op.index("ParameterError err = parse_args(argc, argv);")
    blk = op[s2:s2 + 3000]
    pmap = [{"param": a, "result": b} for a, b in re.findall(
        r"else if\(err == (PARAM_\w+)\)\s*result = (CURLE_\w+);", blk)]
    default = re.search(r"else\s*result = (CURLE_\w+);\s*\}\s*else \{", blk)
    check(default, "operate() default parse_args error mapping not found")
    handled = re.findall(r"(?:if|else if)\(err == (PARAM_\w+)\)\s*(?:;|\{|\n)", blk)
    helpers = src("src/tool_helpers.c")
    p2t = re.findall(r'case (PARAM_\w+):\s*\n\s*return "([^"]*)";', helpers)
    return {
        "doc": codes, "curlcode_enum": enum,
        "curl_last_follows": enum[-1]["name"],
        "parse_args_error_to_exit": {
            "source": f"src/tool_operate.c:{lineno(op, s2)}",
            "specific": pmap,
            "informational_requests_exit_0": sorted(
                x for x in handled if x not in {p["param"] for p in pmap}),
            "default": default.group(1),
        },
        "param2text": {"source": "src/tool_helpers.c",
                       "messages": [{"param": a, "text": b} for a, b in p2t]},
    }, disc


# --------------------------------------------------------------------------
# 5. environment and config files
# --------------------------------------------------------------------------

def parse_env():
    tool_files = sorted(f for f in os.listdir(ROOT / "src")
                        if f.endswith((".c", ".h")))
    hits, comment_lines, total_lines = [], [], 0
    for f in tool_files:
        text = src(f"src/{f}")
        in_comment = False
        for i, line in enumerate(text.splitlines(), 1):
            has = re.search(r"getenv\(", line) is not None
            was = in_comment
            # crude comment state: a line is "comment" if inside /* */ or
            # the call sits after an opening /* on the same line
            pos = line.find("getenv(")
            if "/*" in line and (not has or line.find("/*") < pos):
                in_comment = "*/" not in line[line.find("/*"):]
                inline = has
            else:
                inline = False
                if in_comment and "*/" in line:
                    in_comment = False
            if has:
                total_lines += 1
                if was or inline:
                    comment_lines.append(f"src/{f}:{i}")
                    continue
                m = re.search(r"\b(curl_getenv|getenv)\(\s*(\"([^\"]+)\"|([^)]+))\)", line)
                check(m, f"src/{f}:{i}: getenv call not parsed: {line.strip()}")
                hits.append({
                    "file": f"src/{f}", "line": i, "helper": m.group(1),
                    "name": m.group(3), "expr": m.group(4),
                    "context": line.strip(),
                })
    check(len(hits) + len(comment_lines) == total_lines,
          "getenv hits + comment mentions != lines containing getenv(")
    names = {h["name"] for h in hits if h["name"]}
    for want in ("CURL_CA_BUNDLE", "SSL_CERT_DIR", "SSL_CERT_FILE",
                 "COLUMNS", "IPFS_GATEWAY", "CURL_MEMDEBUG"):
        check(want in names, f"positive control: {want} not found in src/")
    # dynamic names
    for h in hits:
        if h["expr"]:
            h["dynamic"] = True
    helper = src("lib/getenv.c")
    helper_def = f"lib/getenv.c:{lineno(helper, helper.index('curl_getenv('))}"

    # documented variables
    envdoc = src(f"{DOCDIR}/_ENVIRONMENT.md")
    docs = []
    for m in re.finditer(r"^## `([^`]+)`$", envdoc, re.MULTILINE):
        head = m.group(1)
        first = head.split()[0]
        docs.append({"heading": head, "name": first})
    check(len(docs) == len(re.findall(r"^## ", envdoc, re.MULTILINE)),
          "_ENVIRONMENT.md headings not all parsed")
    # where the documented names are read (tool hits, else lib literal)
    lib_text = {}
    for root, _d, fs in os.walk(ROOT / "lib"):
        for f in fs:
            if f.endswith(".c"):
                p = os.path.relpath(os.path.join(root, f), ROOT)
                lib_text[p] = read(p)
    for d in docs:
        n = d["name"]
        d["read_in_tool"] = sorted(f"{h['file']}:{h['line']}" for h in hits
                                   if h["name"] == n)
        lit = set()
        cands = (['"%s_proxy"'] if n.startswith("[")
                 else [f'"{n}"', f'"{n.lower()}"'])
        for p, t in sorted(lib_text.items()):
            hit = {f"{p}:{lineno(t, mm.start())}" for cand in cands
                   for mm in re.finditer(re.escape(cand), t)}
            if hit:
                SOURCES.add(p)
                lit |= hit
        d["string_literal_in_lib"] = sorted(lit)
        d["where"] = ("tool" if d["read_in_tool"] else
                      "lib" if d["string_literal_in_lib"] else "not-found")
    # names that tool reads through the findfile table
    ff = src("src/tool_findfile.c")
    cl = ff.index("conf_list[] = {")
    clend = ff.index("};", cl)
    flist = scan(ff[cl:clend],
                 r"\{\s*(?P<env>NULL|\"[^\"]*\")\s*,\s*(?P<app>NULL|\"[^\"]*\")"
                 r"\s*,\s*(?P<wo>TRUE|FALSE)\s*\}", lineno(ff, cl))
    table = []
    for m, guard, line in flist:
        if m.group("env") == "NULL":
            continue
        table.append({"order": len(table), "env": m.group("env").strip('"'),
                      "append": None if m.group("app") == "NULL"
                      else m.group("app").strip('"'),
                      "without_dot": m.group("wo") == "TRUE",
                      "guard": guard or None, "line": f"src/tool_findfile.c:{line}"})
    check([t["env"] for t in table if not t["guard"]] ==
          ["CURL_HOME", "XDG_CONFIG_HOME", "HOME", "CURL_HOME", "HOME"],
          "findfile conf_list control failed")
    for d in docs:
        if d["where"] == "not-found" and any(t["env"] == d["name"] for t in table):
            d["where"] = "findfile-table"
    # the XDG/HOME names are also read via findfile (tool) even if no direct hit
    documented = {d["name"] for d in docs}
    undocumented = sorted(n for n in names if n not in documented
                          and n not in {t["env"] for t in table})
    pw = re.search(r"#if defined\(HAVE_GETPWUID\) && defined\(HAVE_GETEUID\)\n"
                   r"\s*\{\n\s*struct passwd \*pw = getpwuid\(geteuid\(\)\);", ff)
    check(pw, "findfile getpwuid fallback not found")
    ffdef = re.search(r"^char \*findfile\(", ff, re.MULTILINE)

    parsecfg = src("src/tool_parsecfg.c")
    pc = {
        "function": "parseconfig",
        "file": "src/tool_parsecfg.c",
        "line": lineno(parsecfg, parsecfg.index("ParameterError parseconfig(")),
        "findfile_call": f"src/tool_parsecfg.c:"
                         f"{lineno(parsecfg, parsecfg.index('findfile('))}",
        "exec_dir_fallback_calls": [
            f"src/tool_parsecfg.c:{lineno(parsecfg, m.start())}"
            for m in re.finditer(r'tool_execpath\("[^"]+"', parsecfg)],
        "exec_dir_fallback_names": re.findall(r'tool_execpath\("([^"]+)"', parsecfg),
    }
    check(pc["exec_dir_fallback_names"], "tool_execpath fallback not found")
    dotscore = src("src/tool_findfile.h")
    callers = []
    for f in tool_files:
        if f in ("tool_findfile.c", "tool_findfile.h"):
            continue
        t = read(f"src/{f}")
        callers += [{"at": f"src/{f}:{lineno(t, mm.start())}",
                     "args": mm.group(1)}
                    for mm in re.finditer(r"\bfindfile\(([^)]*)\)", t)]
    cfg = {
        "finder": {"function": "findfile", "file": "src/tool_findfile.c",
                   "line": lineno(ff, ffdef.start()),
                   "helper_getenv": "curl_getenv"},
        "env_order": table,
        "after_env": "getpwuid(geteuid())->pw_dir checked with the plain file "
                     "name (no dot/underscore variants) when HAVE_GETPWUID && "
                     "HAVE_GETEUID",
        "per_directory_check": "checkhome(): with dotscore tries '.name' then "
                               "'_name'; without, the name as given; first "
                               "file that open()s read-only wins",
        "empty_env_value": "skipped (continue to next entry)",
        "withoutdot_rule": "entries with without_dot=true are tried only when "
                           "dotscore is set; they look for the name minus its "
                           "leading dot (i.e. 'curlrc' under XDG_CONFIG_HOME "
                           "or ~/.config)",
        "dotscore_macro": re.findall(r"#define CURLRC_DOTSCORE \d+[^\n]*", dotscore),
        "callers": callers,
        "parseconfig": pc,
        "files_doc": src(f"{DOCDIR}/_FILES.md").split("# FILES", 1)[1].strip(),
        "needs_manual_reading": [
            ("src/tool_parsecfg.c parseconfig(): the full .curlrc / -K "
             "parsing (quoting, '-' for stdin, option:argument syntax)"),
            ("src/tool_findfile.c findfile(): the withoutdot/dotscore "
             "interplay (dotscore is cleared after the first withoutdot "
             "attempt)"),
        ],
    }
    check(callers and any(c["at"].startswith("src/tool_parsecfg.c") for c in callers),
          "findfile caller in tool_parsecfg.c not found")

    quotes = [
        (f"{DOCDIR}/_ENVIRONMENT.md",
         ("The lower case version has precedence. `http_proxy` is an "
          "exception as it is only\navailable in lower case.")),
        (f"{DOCDIR}/_ENVIRONMENT.md",
         ("This environment variable is ignored\nif Schannel is used as the "
          "TLS backend.")),
        (f"{DOCDIR}/_ENVIRONMENT.md",
         ("This environment variable disables use of the proxy even when "
          "specified with\nthe --proxy option.")),
    ]
    hyp = []
    for path, q in quotes:
        check(" ".join(q.split()) in " ".join(read(path).split()),
              f"hypothesis quote missing from {path}")
        hyp.append({"tag": "hypothesis", "source": path, "claim": " ".join(q.split())})
    return {
        "tool_getenv_hits": sorted(hits, key=lambda h: (h["file"], h["line"])),
        "comment_mentions_skipped": sorted(comment_lines),
        "getenv_helper_definition": helper_def,
        "helper_names": ["getenv", "curl_getenv"],
        "documented": docs,
        "tool_reads_undocumented": undocumented,
        "config_file_lookup": cfg,
        "hypotheses": hyp,
    }, undocumented


# --------------------------------------------------------------------------
# 6. generated files
# --------------------------------------------------------------------------

def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True,
                          text=True, check=False)


def parse_listhelp(opts):
    c = src("src/tool_listhelp.c")
    hdr = src("src/tool_help.h")
    cats = {m.group(1).lower(): int(1 << int(m.group(2))) for m in re.finditer(
        r"^#define CURLHELP_([A-Z0-9]+)\s+\(1 << (\d+)\)", hdr, re.MULTILINE)}
    start = c.index("const struct helptxt helptext[] = {")
    end = c.index("{ NULL, NULL, 0 }", start)
    block = c[start:end]
    ent_re = (r"\{\s*\"(?P<opt>(?:[^\"\\]|\\.)*)\"\s*,\s*\"(?P<desc>(?:[^\"\\]|\\.)*)\""
              r"\s*,\s*(?P<cats>[A-Z0-9_|\s]+?)\s*\}")
    found = scan(block, ent_re, lineno(c, start))
    check(len(found) == len(re.findall(r"^  \{ \"", block, re.MULTILINE)),
          "listhelp entries parsed != line-start '{ \"' count")
    got = []
    for m, guard, line in found:
        got.append({
            "opt": m.group("opt"),
            "desc": m.group("desc").replace('\\"', '"'),
            "categories": sorted(t[len("CURLHELP_"):].lower()
                                 for t in re.findall(r"CURLHELP_[A-Z0-9]+", m.group("cats"))),
            "guard": guard or None, "line": line,
        })
    # expected output of `managen listhelp`, from the .md inputs
    exp = []
    for o in sorted(opts, key=lambda o: o["long"]):
        opt = (f"-{o['short']}, --{o['long']}" if o["short"]
               else f"    --{o['long']}")
        if o["arg"]:
            opt += " " + o["arg"]
        exp.append({"opt": opt, "desc": o["help"],
                    "categories": sorted(o["category"]), "long": o["long"],
                    "guard": (f"!defined(CURL_DISABLE_{m.group(1).upper()})"
                              if (m := re.match(r"(ipfs|httpsig)", o["long"]))
                              else None)})
    disc = []
    if len(got) != len(exp):
        note(disc, "listhelp-entry-count", None, f"file {len(got)} vs managen-from-docs {len(exp)}")
    for g, e in zip(got, exp):
        for k in ("opt", "desc", "categories", "guard"):
            if g[k] != e[k]:
                note(disc, f"listhelp-{k}-differs", e["long"], f"file {g[k]!r} vs generated {e[k]!r}")
    unknown_cats = sorted({x for o in opts for x in o["category"]} - set(cats))
    check(not unknown_cats, f"doc categories without CURLHELP_ define: {unknown_cats}")
    return got, cats, disc


def parse_help_categories(cats):
    """
    Read the `categories[]` table of `src/tool_help.c`.

    It is what `--help category` lists, in its order, and what
    `--help <name>` looks up.
    """
    c = src("src/tool_help.c")
    start = c.index("static const struct category_descriptors categories[] = {")
    end = c.index("};", start)
    block = c[start:end]
    found = re.findall(r'\{ "([a-z0-9]+)", "([^"]*)", CURLHELP_([A-Z0-9]+) \}', block)
    check(len(found) == block.count("CURLHELP_"), "categories[] entries unparsed")
    got = [{"name": n, "desc": d, "category": cat.lower()} for n, d, cat in found]
    for g in got:
        check(g["name"] == g["category"] and g["category"] in cats,
              f"category {g} does not name its CURLHELP_ define")
    # `important` is the default page, not a listed category.
    check({g["name"] for g in got} == set(cats) - {"important"},
          "categories[] differs from the CURLHELP_ defines")
    check(got[0] == {"name": "auth", "desc": "Authentication methods",
                     "category": "auth"}, "categories[] control failed")
    return got


def generated_files(opts):
    listhelp, cats, disc = parse_listhelp(opts)
    help_categories = parse_help_categories(cats)
    mk_am = src("src/Makefile.am")
    mk_cm = src("src/CMakeLists.txt")
    dm = src(f"{DOCDIR}/Makefile.am")
    dc = src(f"{DOCDIR}/CMakeLists.txt")
    for needle, text in (("mkhelp.pl", mk_am), ("mk-file-embed.pl", mk_am),
                         ("tool_hugehelp.c", mk_cm), ("tool_ca_embed.c", mk_cm),
                         ("listhelp", dm), ("curl-listhelp", dc),
                         ("tool_listhelp.c", dc)):
        check(needle in text, f"generator wiring '{needle}' not found")
    for p in ("scripts/managen", "src/mkhelp.pl", "src/mk-file-embed.pl"):
        check((ROOT / p).is_file(), f"{p} missing")
        SOURCES.add(p)

    def tracked(p):
        return git("ls-files", "--error-unmatch", p).returncode == 0

    def ignored(p):
        return git("check-ignore", "-q", p).returncode == 0

    files = [
        {"output": "src/tool_listhelp.c",
         "generator": "scripts/managen listhelp",
         "invocation": "make -C docs/cmdline-opts listhelp (autotools); "
                       "target curl-listhelp (CMake); output redirected into "
                       "src/tool_listhelp.c",
         "inputs": ["docs/cmdline-opts/*.md (Long, Short, Arg, Help, Category)",
                    "src/tool_help.h (CURLHELP_* category list)"],
         "committed_in_tree": tracked("src/tool_listhelp.c"),
         "consumers": ["src/tool_help.c"],
         "verified_against_docs": True,
         "entries": len(listhelp)},
        {"output": "src/tool_help.h (CURLHELP_* #defines)",
         "generator": "scripts/managen listcats",
         "invocation": "make -C docs/cmdline-opts listcats (stated in "
                       "src/tool_help.h comment)",
         "inputs": ["docs/cmdline-opts/*.md Category"],
         "committed_in_tree": tracked("src/tool_help.h"),
         "note": "hand-committed header holding generator output",
         "categories": sorted(cats)},
        {"output": "src/tool_hugehelp.c",
         "generator": "src/mkhelp.pl (reads the plain-text manual on stdin; "
                      "-c gzips it; wrapped in #ifndef HAVE_LIBZ ... #else)",
         "invocation": ("autotools rule in src/Makefile.am; CMake custom "
                        "command in src/CMakeLists.txt; needs Perl"),
         "inputs": [("docs/cmdline-opts/curl.txt (built by "
                     "'scripts/managen ascii' from every option .md + the "
                     "_*.md support pages)")],
         "committed_in_tree": tracked("src/tool_hugehelp.c"),
         "gitignored": ignored("src/tool_hugehelp.c"),
         "present_in_tree": (ROOT / "src/tool_hugehelp.c").exists(),
         "header": "src/tool_hugehelp.h (hand-written, tracked)",
         "consumers": ["src/tool_operate.c hugehelp() for --manual"],
         "without_perl": "autotools writes a stub hugehelp()/showhelp() "
                         "unless a pre-built file exists in the source tree"},
        {"output": "docs/cmdline-opts/curl.1",
         "generator": "scripts/managen mainpage",
         "invocation": "docs/cmdline-opts/CMakeLists.txt, Makefile.am",
         "inputs": ["docs/cmdline-opts/*.md", "docs/cmdline-opts/_*.md"],
         "present_in_tree": (ROOT / "docs/cmdline-opts/curl.1").exists()},
        {"output": "src/tool_ca_embed.c",
         "generator": "src/mk-file-embed.pl --var curl_ca_embed",
         "invocation": "src/Makefile.am, src/CMakeLists.txt (CURL_CA_EMBED "
                       "builds only)",
         "inputs": ["the CA bundle file named by CURL_CA_EMBED"],
         "committed_in_tree": tracked("src/tool_ca_embed.c"),
         "gitignored": ignored("src/tool_ca_embed.c"),
         "present_in_tree": (ROOT / "src/tool_ca_embed.c").exists()},
        {"output": "sinus[] table in src/tool_cb_prg.c",
         "generator": "perl snippet in the comment above the table",
         "invocation": "none; pasted by hand",
         "committed_in_tree": True,
         "note": "inline generated data (200 values)"},
    ]
    check(files[2]["committed_in_tree"] is False,
          "tool_hugehelp.c unexpectedly tracked (generated file in tree)")
    check(listhelp, "no listhelp entries")
    return files, disc, listhelp, help_categories


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    opts, skipped, keycount, unknown, ddisc, dpages = parse_docs()
    table, tdisc = parse_table()
    pairs, xdisc = crosscheck(opts, table)
    wo, wdisc = parse_writeout()
    ex, edisc = parse_exitcodes()
    env, _undoc = parse_env()
    gen, gdisc, listhelp, help_categories = generated_files(opts)

    # positive controls on well-known entries
    bylong = {o["long"]: o for o in opts}
    out = bylong["output"]
    check(out["short"] == "o" and out["arg"] == "<file>" and out["multi"] == "per-URL"
          and "important" in out["category"], f"--output control failed: {out}")
    vb = bylong["verbose"]
    check(vb["short"] == "v" and vb["arg"] is None, "--verbose control failed")
    wr = bylong["write-out"]
    check(wr["short"] == "w" and wr["arg"] == "<format>", "--write-out control failed")
    check(bylong["next"]["magic"] == "divider" and bylong["next"]["short"] == ":",
          "--next control failed")
    tab = {e["long"]: e for e in table["entries"]}
    check({"output", "verbose", "write-out", "alpn"} <= set(tab),
          "table lacks a well-known option")
    check(tab["output"]["short"] == "o" and tab["output"]["type"] == "ARG_FILE"
          and tab["verbose"]["type"] == "ARG_BOOL" and tab["verbose"]["short"] == "v"
          and tab["write-out"]["type"] == "ARG_STRG"
          and tab["write-out"]["short"] == "w", "table control failed")
    check(tab["alpn"]["flags"] == ["ARG_NO", "ARG_TLS"], "alpn ARG_NO control failed")
    check(len(opts) == len(dpages) == 278 or len(opts) == len(dpages),
          "option counts")
    # independent count: '^Long:' lines in the option files
    nlong = sum(len(re.findall(r"^Long: ", read(f"{DOCDIR}/{o['file']}"), re.MULTILINE))
                for o in opts)
    check(nlong == len(opts), "Long: line count != options parsed")
    # every doc option is in the table and vice versa is the crosscheck;
    # sanity: the number of pairs equals the number of docs unless unmatched
    unmatched_docs = [d for d in xdisc if d["kind"] == "doc-option-not-in-table"]
    check(len(pairs) + len(unmatched_docs) == len(opts), "pairing lost options")
    # table entries covered by some doc
    check(len({p["table"] for p in pairs}) == len(pairs),
          "two doc options map to one table entry")

    disc = sorted(ddisc + tdisc + xdisc + wdisc + edisc + gdisc,
                  key=lambda d: (d["kind"], str(d["long"]), d["detail"]))
    kinds = {}
    for d in disc:
        kinds[d["kind"]] = kinds.get(d["kind"], 0) + 1

    data = {
        "doc_options": sorted(opts, key=lambda o: o["long"]),
        "doc_files_skipped": skipped,
        "doc_frontmatter_key_counts": dict(sorted(keycount.items())),
        "doc_frontmatter_unknown_keys": unknown,
        "option_table": table,
        "doc_table_pairs": sorted(pairs, key=lambda p: p["doc"]),
        "write_out": wo,
        "exit_codes": ex,
        "environment": env,
        "generated_files": gen,
        "tool_listhelp_entries": listhelp,
        "help_categories": help_categories,
        "discrepancies": disc,
        "discrepancy_counts": dict(sorted(kinds.items())),
    }

    # ---- summary
    n_tab_guard = sum(1 for e in table["entries"] if e["guard"])
    md = []

    def emit(*parts):
        md.extend(parts)

    emit("# curl command-line tool surface\n")
    emit("Derived from `docs/cmdline-opts/*.md` frontmatter, the `aliases[]` "
              "option table in `src/tool_getparam.c`, `src/tool_writeout.c`, "
              "`docs/cmdline-opts/_EXITCODES.md` + `include/curl/curl.h`, "
              "`docs/cmdline-opts/_ENVIRONMENT.md` + `getenv` hits in `src/`, "
              "`src/tool_findfile.c`, and the build rules for generated "
              "files. Full records are in `cli.json`.\n")
    emit(f"- option docs parsed: {len(opts)} (DPAGES in "
              f"docs/cmdline-opts/Makefile.inc lists {len(dpages)})")
    emit(f"- option docs skipped: {len(skipped)} "
              f"({sum(1 for s in skipped if s['file'].startswith('_'))} `_*.md` "
              "support pages, `MANPAGE.md`, build files)")
    emit(f"- option table entries: {len(table['entries'])} "
              f"({n_tab_guard} behind preprocessor guards); `cmdline_t` enum "
              f"entries: {table['enum_count']}")
    emit(f"- doc/table pairs: {len(pairs)}")
    emit(f"- --write-out table variables: {len(wo['variables'])}, special "
              f"forms: {len(wo['special_forms'])}, time specifiers: "
              f"{len(wo['time_format_specifiers'])}")
    emit(f"- exit codes documented: {len(ex['doc'])}; CURLcode values: "
              f"{len(ex['curlcode_enum'])}")
    emit(f"- tool getenv call sites: {len(env['tool_getenv_hits'])}; "
              f"documented env vars: {len(env['documented'])}")
    emit(f"- tool_listhelp.c entries: {len(listhelp)}")
    emit(f"- `--help` categories (tool_help.c): {len(help_categories)}\n")

    emit("## Frontmatter keys\n")
    emit(md_table(["key", "options with it"],
                       [[k, v] for k, v in sorted(keycount.items())]))
    emit("Unknown keys (not in the set above the generator knows): "
              + (", ".join(f"{k} ({len(v)})" for k, v in unknown.items())
                 if unknown else "none") + "\n")
    emit("Skipped in `docs/cmdline-opts/`:\n")
    emit(md_table(["file", "reason"],
                       [[s["file"], s["reason"]] for s in skipped]))

    emit("## Discrepancies\n")
    if kinds:
        emit(md_table(["kind", "count"], [[k, v] for k, v in kinds.items()]))
        emit(md_table(["kind", "item", "detail"],
                           [[d["kind"], d["long"], d["detail"]] for d in disc
                            if d["kind"] != "tls-flag-vs-Requires-TLS"]))
        emit("Rows for `tls-flag-vs-Requires-TLS` are in the JSON only "
                  "(ARG_TLS marks nearly every TLS option; the docs' "
                  "`Requires:` key rarely says so).\n")
    else:
        emit("none\n")

    emit("## Option table (`src/tool_getparam.c`)\n")
    emit(f"ARG types: {', '.join(f'{k}={v}' for v, k in sorted(table['arg_types'].items()))}; "
              f"flags: {', '.join(f'{k}=0x{v:x}' for k, v in sorted(table['arg_flags'].items()))}. "
              f"Longest long name: {table['max_long_name_len']} "
              f"(`MAX_OPTION_LEN` for `--name=value` is "
              f"{table['max_option_len_in_getparameter']}).\n")
    emit(md_table(
        ["long", "short", "type", "flags", "cmd", "guard"],
        [[e["long"], e["short"] or "", e["type"], e["flags"], e["cmd"],
          e["guard"] or ""] for e in table["entries"]]))

    emit("## Documented options\n")
    emit(md_table(
        ["long", "short", "arg", "multi", "category", "protocols", "requires",
         "mutexed", "scope", "added", "extra"],
        [[o["long"], o["short"] or "", o["arg"] or "", o["multi"], o["category"],
          o["protocols"], o["requires"], o["mutexed"], o["scope"] or "",
          o["added"],
          ", ".join(x for x in (
              f"magic={o['magic']}" if o["magic"] else "",
              f"experimental={o['experimental']}" if o["experimental"] else "",
              f"tags={' '.join(o['tags'])}" if o["tags"] else "") if x)]
         for o in data["doc_options"]]))

    emit("## --write-out variables\n")
    emit(md_table(
        ["name", "type", "reads", "json", "doc added"],
        [[v["name"], v["type"], v["curlinfo"] or v["reads_source"] or "",
          "yes" if v["json_member"] else "no", v["doc_added"] or ""]
         for v in wo["variables"]]))
    emit("Special forms: " + ", ".join(f"`{s['form']}`" for s in wo["special_forms"])
              + ". Time specifiers: " + " ".join(wo["time_format_specifiers"]) + "\n")

    emit("## Exit codes\n")
    emit(md_table(["code", "CURLcode", "text"],
                       [[c["code"], c.get("curle", ""), c["text"][:90]] for c in ex["doc"]]))
    pm = ex["parse_args_error_to_exit"]
    emit("parse_args error to exit status (`" + pm["source"] + "`): "
              + ", ".join(f"{p['param']} -> {p['result']}" for p in pm["specific"])
              + f"; any other error -> {pm['default']}; "
              + ", ".join(pm["informational_requests_exit_0"])
              + " -> exit 0 after printing.\n")

    emit("## Environment variables read by the tool (`src/`)\n")
    emit(md_table(["name / expr", "helper", "location"],
                       [[h["name"] or f"<{h['expr']}>", h["helper"],
                         f"{h['file']}:{h['line']}"] for h in env["tool_getenv_hits"]]))
    emit("Documented in `_ENVIRONMENT.md`:\n")
    emit(md_table(["name", "read in tool", "string literal in lib", "where"],
                       [[d["name"], d["read_in_tool"], d["string_literal_in_lib"][:3],
                         d["where"]] for d in env["documented"]]))
    cfg = env["config_file_lookup"]
    emit("## Config file lookup (`findfile`, `src/tool_findfile.c`)\n")
    emit(md_table(["order", "env", "append", "without dot", "guard", "line"],
                       [[t["order"], t["env"], t["append"] or "", t["without_dot"],
                         t["guard"] or "", t["line"]] for t in cfg["env_order"]]))
    emit(f"{cfg['after_env']}. Callers: "
              + ", ".join(c["at"] for c in cfg["callers"])
              + f". Executable-directory fallback in `parseconfig` "
              f"({cfg['parseconfig']['file']}:{cfg['parseconfig']['line']}) "
              f"tries {', '.join(cfg['parseconfig']['exec_dir_fallback_names'])}."
              " Needs manual reading: " + "; ".join(cfg["needs_manual_reading"]) + "\n")
    emit("Hypotheses from prose docs (claims to verify):\n")
    emit(md_table(["source", "claim"],
                       [[h["source"], h["claim"]] for h in env["hypotheses"]]))

    emit("## Generated files (regenerate, do not copy)\n")
    emit(md_table(["output", "generator", "tracked", "inputs"],
                       [[g["output"], g["generator"],
                         g.get("committed_in_tree", ""), g.get("inputs", "")]
                        for g in gen]))

    write(NAME, data, "\n".join(md), SOURCES)
    print(f"cli: {len(opts)} doc options, {len(table['entries'])} table entries, "
          f"{len(wo['variables'])} write-out vars, {len(ex['doc'])} exit codes, "
          f"{len(env['tool_getenv_hits'])} getenv sites, {len(disc)} discrepancies")
    for k, v in kinds.items():
        print(f"  {v:3d} {k}")


if __name__ == "__main__":
    main()
