#!/usr/bin/env python3
"""
Inventory of the libcurl C ABI: exported functions, every constant the
public headers define (with the value the compiler computes), the layout of
every public struct, typedef sizes, symbol version history, and the
library's link-level identity (soname, version script, pkg-config).

Values and layouts are not parsed out of the headers by hand: a probe
program is compiled with gcc against include/ and run, so the numbers are
the ones an application compiled against these headers bakes in. Layouts
are for the build target (recorded as `target`).
"""

import pathlib
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common
from common import ROOT, check

SCRATCH = None  # set in main()
HEADERS = ["curl.h", "curlver.h", "easy.h", "header.h", "mprintf.h",
           "multi.h", "options.h", "system.h", "urlapi.h", "websockets.h",
           "typecheck-gcc.h", "stdcheaders.h"]
# typecheck-gcc.h only adds compile-time type checking wrappers around
# functions (API, not ABI; the options inventory covers it); stdcheaders.h
# is not included by curl.h. Both are listed so every header is accounted for.
NOT_PROBED = {"typecheck-gcc.h": "compile-time option type checks only",
              "stdcheaders.h": "not included by curl/curl.h"}
# Listed as live in symbols-in-versions but not defined by the headers on
# this target with the probe's flags: CURL_PULL_SYS_POLL_H is AIX-only in
# system.h, CURL_STRICTER only exists under CURL_NO_OLDIES, and CURLWARNING
# lives in typecheck-gcc.h, which the probe disables.
SIV_NOT_IN_HEADERS = {"CURL_PULL_SYS_POLL_H", "CURL_STRICTER", "CURLWARNING"}
CFLAGS = ["-std=gnu17", "-I", str(ROOT / "include"),
          "-DCURL_DISABLE_TYPECHECK"]


def gcc(args, **kw):
    return subprocess.run(["gcc", *CFLAGS, *args], check=False,
                          capture_output=True, text=True, **kw)


# ---------------------------------------------------------------- preprocess

def preprocess():
    """
    Return (macros, code) from the public headers only. `macros` maps a
    name to {header, params, body}; `code` maps a header to its
    preprocessed declarations.
    """
    src = SCRATCH / "pp.c"
    src.write_text("#include <curl/curl.h>\n")
    r = gcc(["-E", "-dD", str(src)])
    check(r.returncode == 0, f"preprocessing failed: {r.stderr}")
    macros, code, cur = {}, {}, None
    for line in r.stdout.splitlines():
        m = re.match(r'^# \d+ "([^"]*)"', line)
        if m:
            p = m.group(1)
            cur = p.split("include/curl/", 1)[1] if "include/curl/" in p and \
                p.startswith(str(ROOT)) else None
            continue
        if cur is None:
            continue
        m = re.match(r"^#define (\w+)(\([^)]*\))?\s?(.*)$", line)
        if m:
            name, params, body = m.groups()
            macros[name] = {"header": cur, "params": params,
                            "body": body.strip()}
            continue
        m = re.match(r"^#undef (\w+)", line)
        if m:
            macros.pop(m.group(1), None)
            continue
        code.setdefault(cur, []).append(line)
    return macros, {h: "\n".join(v) for h, v in code.items()}


def split_top(text, sep, opens="({[", closes=")}]"):
    out, depth, cur = [], 0, []
    for ch in text:
        if ch in opens:
            depth += 1
        elif ch in closes:
            depth -= 1
        if ch == sep and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return [s.strip() for s in out]


def strip_attrs(text):
    """
    Remove `__attribute__((...))` groups; return (text, deprecated msg or
    None).
    """
    dep = None
    while True:
        i = text.find("__attribute__")
        if i < 0:
            return " ".join(text.split()), dep
        j, depth = text.index("(", i), 0
        k = j
        while True:
            if text[k] == "(":
                depth += 1
            elif text[k] == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        attr = text[i:k + 1]
        m = re.search(r'deprecated\s*\(\s*((?:"[^"]*"\s*)+)\)', attr)
        if m:
            dep = "".join(re.findall(r'"([^"]*)"', m.group(1)))
        elif re.search(r"\bdeprecated\b", attr):
            dep = ""
        text = text[:i] + " " + text[k + 1:]


def declarator_name(decl):
    m = re.search(r"\(\s*\*\s*(\w+)\s*\)", decl)
    if m:
        return m.group(1)
    decl = re.sub(r"\[[^\]]*\]", "", decl)
    return re.findall(r"\w+", decl)[-1]


def parse_fields(body, prefix=""):
    fields = []
    for decl in split_top(body, ";"):
        if not decl:
            continue
        if "{" in decl:
            inner = decl[decl.index("{") + 1:decl.rindex("}")]
            name = decl[decl.rindex("}") + 1:].strip()
            kind = decl.split("{")[0].strip()
            fields.append({"name": prefix + name, "decl": kind + " {...}"})
            fields += parse_fields(inner, prefix + name + ".")
            continue
        decl, _ = strip_attrs(decl)
        parts = split_top(decl, ",")
        base = re.match(r"^(.*?)(\(?\s*\**\s*\w+\s*(\[[^\]]*\])*\s*\)?\s*"
                        r"(\(.*\))?)$", parts[0])
        for i, p in enumerate(parts):
            bits = re.match(r"^(.*?)\s*:\s*(\d+)$", p)
            rec = {"name": prefix + declarator_name(bits.group(1) if bits
                                                    else p),
                   "decl": p if i == 0 else f"{base.group(1).strip()} {p}"}
            if bits:
                rec["bit-width"] = int(bits.group(2))
            fields.append(rec)
    return fields


def parse_code(code):
    funcs, enums, structs, typedefs, opaque = [], [], {}, [], set()
    for header, text in sorted(code.items()):
        for stmt in split_top(text, ";", "{", "}"):
            stmt = " ".join(stmt.split())
            if not stmt:
                continue
            if stmt.startswith("extern \"C\""):
                continue
            body = None
            if "{" in stmt:
                body = stmt[stmt.index("{") + 1:stmt.rindex("}")]
            if stmt.startswith("typedef"):
                rest = stmt[len("typedef"):].strip()
                if body is not None:
                    tag = re.match(r"^(enum|struct|union)\s*(\w*)", rest)
                    alias = stmt[stmt.rindex("}") + 1:].strip()
                    if tag.group(1) == "enum":
                        enums.append(parse_enum(header, alias,
                                                tag.group(2), body))
                    else:
                        structs[f"{tag.group(1)} {tag.group(2)}" if
                                tag.group(2) else alias] = {
                            "header": header,
                            "fields": parse_fields(body)}
                    typedefs.append({"name": alias, "header": header,
                                     "decl": stmt})
                else:
                    clean, dep = strip_attrs(rest)
                    typedefs.append({"name": declarator_name(clean),
                                     "header": header,
                                     "decl": "typedef " + clean,
                                     "deprecated": dep})
                continue
            m = re.match(r"^(struct|union) (\w+)$", stmt)
            if m:
                opaque.add(f"{m.group(1)} {m.group(2)}")
                continue
            m = re.match(r"^(struct|union|enum) (\w+) \{", stmt)
            if m and stmt.endswith("}"):
                if m.group(1) == "enum":
                    enums.append(parse_enum(header, None, m.group(2), body))
                else:
                    structs[f"{m.group(1)} {m.group(2)}"] = {
                        "header": header, "fields": parse_fields(body)}
                continue
            clean, dep = strip_attrs(stmt)
            m = re.match(r"^(.*?)\b(curl_\w+)\s*\((.*)\)$", clean)
            check(m is not None, f"unclassified declaration in {header}: "
                  f"{stmt!r}")
            params = m.group(3).strip()
            funcs.append({
                "name": m.group(2), "header": header,
                "returns": m.group(1).strip(),
                "params": [] if params == "void" else split_top(params, ","),
                "variadic": params.endswith("..."),
                "prototype": clean, "deprecated": dep})
    for t in typedefs:
        m = re.match(r"^typedef (struct|union) (\w+) \w+$", t["decl"])
        if m and f"{m.group(1)} {m.group(2)}" not in structs:
            opaque.add(f"{m.group(1)} {m.group(2)}")
    return funcs, enums, structs, typedefs, sorted(opaque - set(structs))


def parse_enum(header, alias, tag, body):
    members = []
    for item in split_top(body, ","):
        if not item:
            continue
        item, dep = strip_attrs(item)
        name, _, expr = item.partition("=")
        members.append({"name": name.strip(), "expr": expr.strip() or None,
                        "deprecated": dep})
    return {"typedef": alias or None, "tag": tag or None, "header": header,
            "members": members}


# --------------------------------------------------------------------- probe

TYPENAMES = ["char", "signed char", "unsigned char", "short",
             "unsigned short", "int", "unsigned int", "long",
             "unsigned long", "long long", "unsigned long long", "float",
             "double", "char *", "const char *", "void *"]

PROBE_PRELUDE = r"""
#include <curl/curl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
static void pi(const char *n, const char *t, long long v)
{ printf("V\t%s\t%s\t%lld\n", n, t, v); }
static void pu(const char *n, const char *t, unsigned long long v)
{ printf("V\t%s\t%s\t%llu\n", n, t, v); }
static void pd(const char *n, const char *t, double v)
{ printf("V\t%s\t%s\t%.17g\n", n, t, v); }
static void ps(const char *n, const char *t, const char *v)
{ printf("V\t%s\t%s\t\"%s\"\n", n, t, v); }
static void pp(const char *n, const char *t, const void *v)
{ printf("V\t%s\t%s\t%p\n", n, t, v); }
#define TN(x) _Generic((x), """ + ", ".join(
    f'{t}: "{t}"' for t in TYPENAMES) + r""", default: "other")
#define P(x) _Generic((x), char *: ps, const char *: ps, void *: pp, \
  float: pd, double: pd, unsigned int: pu, unsigned long: pu, \
  unsigned long long: pu, default: pi)(#x, TN(x), (x))
#define S(t) printf("S\t%s\t%zu\t%zu\n", #t, sizeof(t), _Alignof(t))
#define O(s, f) printf("O\t%s\t%s\t%zu\t%zu\n", #s, #f, offsetof(s, f), \
  sizeof(((s *)0)->f))
#define B(s, f) do { s x_; unsigned char *p_ = (unsigned char *)&x_; \
  size_t i_; int b_; memset(&x_, 0, sizeof(x_)); x_.f = 1; \
  for(i_ = 0; i_ < sizeof(x_); i_++) for(b_ = 0; b_ < 8; b_++) \
    if(p_[i_] & (1 << b_)) { printf("B\t%s\t%s\t%zu\t%d\n", #s, #f, \
      i_, b_); i_ = sizeof(x_); break; } } while(0)
#define F(f) printf("F\t%s\t%d\n", #f, (void *)&f != NULL)
int main(void)
{
"""


def run_probe(lines):
    """
    Compile `lines` (one statement each) into the probe; drop lines that
    fail to compile and retry. Returns (stdout, dropped lines).
    """
    lines, dropped = list(lines), []
    first = PROBE_PRELUDE.count("\n") + 1
    for _ in range(50):
        src = SCRATCH / "probe.c"
        src.write_text(PROBE_PRELUDE + "\n".join(lines) +
                       "\nreturn 0;\n}\n")
        exe = SCRATCH / "probe"
        r = gcc(["-Werror=int-conversion", "-Wno-deprecated-declarations",
                 "-o", str(exe), str(src)])
        if r.returncode == 0:
            out = subprocess.run([str(exe)], capture_output=True, text=True,
                                 check=True).stdout
            return out, dropped
        # An error inside a header names the probe line only in the
        # "in expansion of macro" notes that follow it.
        bad, pending = set(), False
        for diag in r.stderr.splitlines():
            if ": error:" in diag:
                pending = True
            m = re.search(r"probe\.c:(\d+):\d+: (error|note)", diag)
            if m and pending and int(m.group(1)) >= first:
                bad.add(int(m.group(1)) - first)
                pending = False
        bad = {b for b in bad if 0 <= b < len(lines)}
        check(bad, f"probe failed outside the probe lines:\n{r.stderr}")
        dropped += [lines[b] for b in bad]
        lines = [line for i, line in enumerate(lines) if i not in bad]
    sys.exit("abi.py: check failed: probe did not converge")


# ----------------------------------------------------------- other sources

def symbols_in_versions():
    rows = []
    for line in common.read("docs/libcurl/symbols-in-versions").splitlines():
        if not re.match(r"^[A-Za-z_]", line):
            continue
        cols = line.split()
        check(2 <= len(cols) <= 4, f"bad symbols-in-versions row {line!r}")
        cols += ["-"] * (4 - len(cols))
        rows.append({"name": cols[0], "introduced": cols[1],
                     "deprecated": None if cols[2] == "-" else cols[2],
                     "last": None if cols[3] == "-" else cols[3]})
    return rows


def def_exports():
    names = []
    for line in common.read("lib/libcurl.def").splitlines():
        line = line.strip()
        if line and line != "EXPORTS":
            names.append(line)
    return names


def lib_defined_curl_functions():
    """
    Heuristic: functions named curl_* defined (not declared) in lib/.
    The linker version script exports every global `curl_*`, so anything
    here that is not public still leaks into the dynamic symbol table.
    """
    found = {}
    for p in sorted((ROOT / "lib").rglob("*.c")):
        lines = p.read_text(errors="replace").splitlines()
        for i, line in enumerate(lines):
            m = re.match(r"^(?!static\b)[A-Za-z_][\w \*]*?\b(curl_\w+)\s*\(",
                         line)
            if not m or line.rstrip().endswith(";"):
                continue
            nxt = "\n".join(lines[i:i + 8])
            if re.search(r"\)\s*\{", nxt) and ";" not in nxt.split("{")[0]:
                found.setdefault(m.group(1), []).append(
                    f"{p.relative_to(ROOT)}:{i + 1}")
    return found


STRERROR = {"curl_easy_strerror": ("CURLcode", "e"),
            "curl_multi_strerror": ("CURLMcode", "m"),
            "curl_share_strerror": ("CURLSHcode", "s"),
            "curl_url_strerror": ("CURLUcode", "u")}
C_STRING = r'((?:"(?:[^"\\]|\\.)*"\s*)+)'


def c_string(lit):
    return "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', lit))


def strerror_tables():
    """
    Return the message each *_strerror function gives per code name.

    lib/strerror.c switches on the code under CURLVERBOSE; a build without
    it returns only the strings of its `#else` branch.
    """
    text = common.read("lib/strerror.c")
    tables = {}
    for fn, (enum, _) in STRERROR.items():
        m = re.search(rf"^const char \*{fn}\({enum} \w+\)\n\{{\n(.*?)^\}}",
                      text, re.MULTILINE | re.DOTALL)
        check(m is not None, f"{fn} not found in lib/strerror.c")
        verbose, _, quiet = m.group(1).partition("#else")
        check(verbose.lstrip().startswith("#ifdef CURLVERBOSE") and quiet,
              f"{fn}: no CURLVERBOSE split")
        # The message for an unknown code is the switch's last return;
        # labels ending in `break` (or `default`) fall through to it.
        returns = list(re.finditer(rf"return {C_STRING};", verbose))
        check(returns, f"{fn}: no returns")
        fallback = c_string(returns[-1].group(1))
        messages, labels, to_fallback = {}, [], []
        for tok in re.finditer(rf"case (\w+):|(default):|(break);|"
                               rf"return {C_STRING};",
                               verbose[:returns[-1].start()]):
            if tok.group(1):
                labels.append(tok.group(1))
            elif tok.group(2):
                labels.append("default")
            elif tok.group(3):
                to_fallback += labels
                labels = []
            else:
                check(labels, f"{fn}: return without case label")
                for label in labels:
                    messages[label] = c_string(tok.group(4))
                labels = []
        to_fallback += labels
        tables[fn] = {"enum": enum, "messages": messages,
                      "unknown": fallback,
                      "labels-reaching-unknown": to_fallback,
                      "without-verbose-strings": [
                          c_string(lit) for lit in
                          re.findall(rf"return {C_STRING};", quiet)]}
    return tables


def check_strerror_against_test1538(tables, constants):
    """Compare the parsed tables with test 1538, which prints them all."""
    by_value = {}
    for c in constants:
        if c["kind"] == "enum":
            by_value.setdefault((c["enum"], int(c["value"])), []).append(
                c["name"])
    body = common.read("tests/data/test1538")
    out = body[body.index("<stdout>\n") + 9:body.index("</stdout>")]
    seen = 0
    for line in out.splitlines():
        m = re.match(r"^([emsu])(-?\d+): (.*)$", line)
        if not m:
            continue
        fn = next(f for f, (_, p) in STRERROR.items() if p == m.group(1))
        t = tables[fn]
        names = by_value.get((t["enum"], int(m.group(2))), [])
        got = {t["messages"][n] for n in names if n in t["messages"]}
        check(len(got) <= 1, f"{fn}: one value, several messages: {names}")
        want = got.pop() if got else t["unknown"]
        check(want == m.group(3), f"test1538 says {line!r}, parsed {want!r}")
        seen += 1
    # lib1538 prints every value from the lowest member to the _LAST one.
    want_lines = 0
    for t in tables.values():
        vals = [v for (e, v) in by_value if e == t["enum"]]
        want_lines += max(vals) - min(vals) + 1
    check(seen == want_lines,
          f"test1538 lines checked: {seen}, expected {want_lines}")


def function_docs(funcs):
    """Attach each function's man page metadata and RETURN VALUE text."""
    # A page may document several functions (curl_mprintf.md covers the
    # whole printf family): fall back to the page whose SYNOPSIS names it.
    synopsis = {}
    for page in sorted((ROOT / "docs/libcurl").glob("curl_*.md")):
        m = re.search(r"^# SYNOPSIS\n(.*?)(?=^# )", page.read_text(),
                      re.MULTILINE | re.DOTALL)
        for name in set(re.findall(r"\b(curl_\w+)\s*\(", m.group(1)
                                   if m else "")):
            synopsis.setdefault(name, []).append(
                str(page.relative_to(ROOT)))
    for f in funcs:
        path = f"docs/libcurl/{f['name']}.md"
        if not (ROOT / path).exists():
            pages = synopsis.get(f["name"], [])
            if len(pages) != 1:
                f["doc"] = None
                continue
            path = pages[0]
        meta, body = common.frontmatter(common.read(path))
        m = re.search(r"^# RETURN VALUE\n\n(.*?)(?=^# |\Z)", body,
                      re.MULTILINE | re.DOTALL)
        f["doc"] = {"path": path, "added-in": meta.get("Added-in"),
                    "protocol": meta.get("Protocol"),
                    "return-value": m.group(1).strip() if m else None}


def soname():
    vals = dict(re.findall(r"^(VERSION\w+)=(\S+)$",
                           common.read("lib/Makefile.soname"), re.MULTILINE))
    change, add, dele = (int(vals[k]) for k in
                         ("VERSIONCHANGE", "VERSIONADD", "VERSIONDEL"))
    major = change - dele
    return {"libtool-version-info": f"{change}:{add}:{dele}",
            "soname": f"libcurl.so.{major}",
            "real-name": f"libcurl.so.{major}.{dele}.{add}"}


def versioned_symbols():
    text = common.read("lib/CMakeLists.txt")
    prefixes = re.findall(
        r'(?:if|elseif)\((CURL_\w+)\)\s*\n\s*set\(CURL_LIBCURL_VERSIONED_'
        r'SYMBOLS_PREFIX "(\w+)"\)', text)
    return {"script": common.read("lib/libcurl.vers.in"),
            "default-enabled": bool(re.search(
                r'option\(CURL_LIBCURL_VERSIONED_SYMBOLS "[^"]*" ON\)',
                text)),
            "prefix-by-backend": [{"condition": c, "prefix": p}
                                  for c, p in prefixes]}


def curl_config_options():
    text = common.read("curl-config.in")
    return sorted(set(re.findall(r"^\s*(--[\w-]+)(?:=\*)?\)", text, re.MULTILINE)))


def pkgconfig():
    fields = {}
    for line in common.read("libcurl.pc.in").splitlines():
        m = re.match(r"^([\w.]+)\s*([:=])\s*(.*)$", line)
        if m:
            fields[m.group(1)] = m.group(3)
    return fields


# ---------------------------------------------------------------------- main

def main():
    global SCRATCH
    with tempfile.TemporaryDirectory(prefix="inventory-abi-") as tmp:
        SCRATCH = pathlib.Path(tmp)
        generate()


def generate():
    target = subprocess.run(["gcc", "-dumpmachine"], capture_output=True,
                            text=True, check=True).stdout.strip()

    on_disk = sorted(p.name for p in (ROOT / "include/curl").glob("*.h"))
    check(on_disk == sorted(HEADERS),
          f"header set changed: {sorted(set(on_disk) ^ set(HEADERS))}")

    macros, code = preprocess()
    seen = set(code) | {m["header"] for m in macros.values()}
    check(seen == set(HEADERS) - set(NOT_PROBED),
          f"probed headers {sorted(seen)}")
    funcs, enums, structs, typedefs, opaque = parse_code(code)

    # Positive control: one prototype per CURL_EXTERN in the raw headers.
    raw_extern = sum(len(re.findall(r"^CURL_EXTERN\b",
                                    common.read(f"include/curl/{h}"), re.MULTILINE))
                     for h in HEADERS)
    check(len(funcs) == raw_extern,
          f"{len(funcs)} prototypes parsed, {raw_extern} CURL_EXTERN lines")
    raw_structs = sum(len(re.findall(r"^\s*(?:typedef\s+)?struct\s+\w+\s*\{",
                                     common.read(f"include/curl/{h}"), re.MULTILINE))
                      for h in HEADERS)
    check(len(structs) == raw_structs,
          f"{len(structs)} structs parsed, {raw_structs} in headers")

    # ---- probe everything
    enum_names = [m["name"] for e in enums for m in e["members"]]
    check(len(enum_names) == len(set(enum_names)), "duplicate enum constant")
    obj_macros = sorted(n for n, m in macros.items()
                        if m["params"] is None and m["body"])
    lines = [f"P({n});" for n in enum_names + obj_macros]
    lines += [f"F({f['name']});" for f in funcs]
    type_names = [t["name"] for t in typedefs] + sorted(structs)
    lines += [f"S({t});" for t in type_names]
    for s, info in sorted(structs.items()):
        lines += [f"{'B' if 'bit-width' in f else 'O'}({s}, {f['name']});"
                  for f in info["fields"] if not f["decl"].endswith("{...}")]
    out, dropped = run_probe(lines)

    values, sizes, offsets, bitpos, linked = {}, {}, {}, {}, set()
    for line in out.splitlines():
        kind, *rest = line.split("\t")
        if kind == "V":
            values[rest[0]] = {"c-type": rest[1], "value": rest[2]}
        elif kind == "S":
            sizes[rest[0]] = {"size": int(rest[1]), "align": int(rest[2])}
        elif kind == "O":
            offsets[rest[0], rest[1]] = (int(rest[2]), int(rest[3]))
        elif kind == "B":
            bitpos[rest[0], rest[1]] = (int(rest[2]), int(rest[3]))
        elif kind == "F":
            linked.add(rest[0])
    dropped_names = {re.match(r"^\w\((.*)\);$", d).group(1) for d in dropped}

    for n in enum_names:
        check(n in values, f"enum constant {n} did not evaluate")
    check(linked == {f["name"] for f in funcs},
          "not every prototype resolved to a function")
    for s, info in structs.items():
        for f in info["fields"]:
            if f["decl"].endswith("{...}"):
                continue
            if "bit-width" in f:
                check((s, f["name"]) in bitpos,
                      f"no bit position for {s}.{f['name']}")
                f["offset"], f["bit"] = bitpos[s, f["name"]]
                continue
            check((s, f["name"]) in offsets, f"no offset for {s}.{f['name']}")
            f["offset"], f["size"] = offsets[s, f["name"]]
        check(s in sizes, f"no size for {s}")
        info.update(sizes[s])
    for t in typedefs:
        t.update(sizes.get(t["name"], {"size": None, "align": None}))

    # Positive controls on known values for this target.
    def v(n):
        return values[n]["value"]
    check(v("CURLE_OK") == "0" and v("CURLE_UNSUPPORTED_PROTOCOL") == "1",
          "CURLcode base values")
    check(v("CURLOPT_URL") == "10002" and v("CURLOPT_WRITEFUNCTION") ==
          "20011", "CURLOPT values")
    check(v("CURLINFO_RESPONSE_CODE") == str(0x200002), "CURLINFO value")
    check(v("CURL_ERROR_SIZE") == "256", "CURL_ERROR_SIZE")
    check(values["LIBCURL_VERSION"]["c-type"] == "char *", "string macro")
    if target.startswith(("x86_64-", "aarch64-")) and "linux" in target:
        check(structs["struct curl_slist"]["size"] == 16 and
              structs["struct curl_slist"]["fields"][1]["offset"] == 8,
              "curl_slist layout on LP64")

    function_docs(funcs)
    constants = [{"name": m["name"], "kind": "enum",
                  "enum": e["typedef"] or f"enum {e['tag']}",
                  "header": e["header"], "expr": m["expr"],
                  "deprecated": m["deprecated"], **values[m["name"]]}
                 for e in enums for m in e["members"]]
    for n in obj_macros:
        rec = {"name": n, "kind": "macro", "header": macros[n]["header"],
               "expr": macros[n]["body"]}
        if n in values:
            rec.update(values[n])
        else:
            check(n in dropped_names, f"macro {n} neither printed nor dropped")
            rec["c-type"], rec["value"] = None, None
        constants.append(rec)
    other_macros = sorted(
        ({"name": n, **m} for n, m in macros.items()
         if m["params"] is not None or not m["body"]),
        key=lambda m: m["name"])

    # ---- symbol history and cross-checks
    siv = symbols_in_versions()
    siv_names = {r["name"] for r in siv}
    header_names = {c["name"] for c in constants} | \
        {m["name"] for m in other_macros}
    discrepancies = []
    for r in siv:
        if r["last"] is None and r["name"] not in header_names:
            # Anything else missing is more likely our parser dropping a
            # name than the C tree's list being wrong: look before adding.
            check(r["name"] in SIV_NOT_IN_HEADERS,
                  f"live symbol {r['name']} not found in headers")
            discrepancies.append({"kind": "siv-live-not-in-headers",
                                  "name": r["name"]})
        if r["last"] is not None and r["name"] in header_names:
            discrepancies.append({"kind": "siv-removed-still-in-headers",
                                  "name": r["name"]})
    internal = re.compile(r"^(CURLINC_|__)")
    # Enum end markers and reserved slots are left out of
    # symbols-in-versions on purpose; their values still matter, since a
    # reserved number must never be reused.
    for n in sorted(header_names - siv_names):
        if internal.match(n):
            continue
        if re.search(r"_LAST(ENTRY)?$", n):
            kind = "sentinel-not-in-siv"
        elif re.search(r"_OBSOLETE\d*$", n):
            kind = "reserved-slot-not-in-siv"
        else:
            kind = "header-name-not-in-siv"
        discrepancies.append({"kind": kind, "name": n})
    exports = def_exports()
    fnames = {f["name"] for f in funcs}
    discrepancies += [{"kind": "def-export-without-prototype", "name": n}
                      for n in sorted(set(exports) - fnames)]
    discrepancies += [{"kind": "prototype-not-in-def", "name": n}
                      for n in sorted(fnames - set(exports))]
    lib_defs = lib_defined_curl_functions()
    leaked = {n: locs for n, locs in sorted(lib_defs.items())
              if n not in fnames}
    discrepancies += [{"kind": "prototype-without-lib-definition-heuristic",
                       "name": n} for n in sorted(fnames - set(lib_defs))]

    discrepancies += [{"kind": "function-without-man-page", "name": f["name"]}
                      for f in funcs if f["doc"] is None]
    strerrors = strerror_tables()
    check_strerror_against_test1538(strerrors, constants)

    deprecated_consts = sum(1 for c in constants if c.get("deprecated")
                            is not None)
    data = {
        "target": target,
        "headers": {h: NOT_PROBED.get(h, "probed") for h in HEADERS},
        "library": {**soname(), "exports-file": "lib/libcurl.def",
                    "versioned-symbols": versioned_symbols(),
                    "curl-config-options": curl_config_options(),
                    "pkg-config": pkgconfig()},
        "functions": sorted(funcs, key=lambda f: f["name"]),
        "constants": sorted(constants, key=lambda c: c["name"]),
        "function-like-and-empty-macros": other_macros,
        "enums": [{"typedef": e["typedef"], "tag": e["tag"],
                   "header": e["header"], "size": sizes.get(
                       e["typedef"] or f"enum {e['tag']}", {}).get("size"),
                   "members": [m["name"] for m in e["members"]]}
                  for e in enums],
        "structs": dict(sorted(structs.items())),
        "opaque-types": opaque,
        "typedefs": sorted(typedefs, key=lambda t: t["name"]),
        "symbol-history": siv,
        "strerror": strerrors,
        "lib-defined-curl-functions-not-public-heuristic": leaked,
        "discrepancies": discrepancies,
    }

    # ---- summary
    lib = data["library"]
    md = ["# libcurl ABI\n",
          ("Exported functions, constants, struct layouts and link-level "
           "identity of libcurl, as an application compiled against "
           "`include/curl/` sees them. Values and layouts come from a probe "
           f"compiled with gcc for `{target}`.\n"),
          (f"- library: `{lib['real-name']}` (soname `{lib['soname']}`, "
           f"libtool `{lib['libtool-version-info']}`)"),
          (f"- exported functions: {len(funcs)} "
           f"({sum(f['variadic'] for f in funcs)} variadic, "
           f"{sum(f['deprecated'] is not None for f in funcs)} deprecated); "
           f"`lib/libcurl.def` lists {len(exports)}"),
          (f"- constants: {len(constants)} ({len(enum_names)} enum members, "
           f"{len(obj_macros)} object-like macros, "
           f"{len(dropped_names & set(obj_macros))} of them not values); "
           f"{deprecated_consts} carry a deprecation attribute"),
          f"- function-like or empty macros: {len(other_macros)}",
          (f"- structs with public layout: {len(structs)}; opaque types: "
           f"{len(opaque)}"),
          (f"- symbols-in-versions rows: {len(siv)} "
           f"({sum(r['last'] is not None for r in siv)} removed, numbers "
           "reserved)"),
          f"- discrepancies: {len(discrepancies)}\n",
          ("Versioned symbols are "
           + ("on" if lib["versioned-symbols"]["default-enabled"] else "off")
           + " by default; when on, the version node name depends on the "
           "TLS backend:\n"),
          common.md_table(["condition", "prefix"],
                          [(p["condition"], p["prefix"]) for p in
                           data["library"]["versioned-symbols"]
                           ["prefix-by-backend"]]),
          "## Functions\n",
          common.md_table(["name", "header", "prototype", "added",
                           "deprecated"],
                          [(f["name"], f["header"], f"`{f['prototype']}`",
                            (f["doc"] or {}).get("added-in", ""),
                            f["deprecated"] if f["deprecated"] is not None
                            else "") for f in data["functions"]]),
          "## Error strings\n",
          ("Returned by the `*_strerror` functions in a build with verbose "
           "strings (the `verbose-strings` test feature); without it they "
           "return only the `#else` strings. Checked line by line against "
           "test 1538.\n"),
          common.md_table(
              ["function", "codes with a message", "unknown code",
               "without verbose strings"],
              [(fn, len(t["messages"]), t["unknown"],
                t["without-verbose-strings"])
               for fn, t in strerrors.items()]),
          "## Structs\n"]
    for s, info in data["structs"].items():
        md += [(f"### `{s}` ({info['header']}): size {info['size']}, "
                f"align {info['align']}\n"),
               common.md_table(
                   ["field", "offset", "size", "declaration"],
                   [(f["name"], f.get("offset", ""),
                     f"{f['bit-width']} bit(s) at bit {f['bit']}"
                     if "bit-width" in f else f.get("size", ""),
                     f"`{f['decl']}`") for f in info["fields"]])]
    kinds = {}
    for d in discrepancies:
        kinds.setdefault(d["kind"], []).append(d["name"])
    md += [
        "## Opaque types\n",
        ", ".join(f"`{o}`" for o in opaque) + "\n",
        "## Enums\n",
        common.md_table(
            ["type", "header", "size", "members"],
            [(e["typedef"] or f"enum {e['tag']}", e["header"], e["size"],
              len(e["members"])) for e in data["enums"]]),
        "## Non-public `curl_*` functions defined in lib/\n",
        ("Found by a source heuristic; the version script "
         "(`global: curl_*`) would export these if they are not static.\n"),
        common.md_table(["name", "defined at"], list(leaked.items())),
        "## Discrepancies\n",
        common.md_table(["kind", "count", "names"],
                        [(k, len(v), ", ".join(f"`{n}`" for n in v))
                         for k, v in sorted(kinds.items())]),
        ("Constants, typedef sizes and the full symbol history are in "
         "`abi.json`.\n"),
    ]

    common.write("abi", data, "\n".join(md), [
        "include/curl/", "docs/libcurl/symbols-in-versions",
        "lib/libcurl.def", "lib/libcurl.vers.in", "lib/Makefile.soname",
        "lib/CMakeLists.txt", "curl-config.in", "libcurl.pc.in", "lib/",
        "lib/strerror.c", "tests/data/test1538", "docs/libcurl/"])


if __name__ == "__main__":
    main()
