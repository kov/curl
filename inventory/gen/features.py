"""
Inventory the feature and backend surface of libcurl.

Covers protocols (scheme table), the curl_version_info feature table,
build options (CMake, configure, CURL_DISABLE_*), backends by category,
the environment variables libcurl reads, and the prose feature list in
docs/FEATURES.md.  Writes inventory/features.json and inventory/features.md.
"""

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common
from common import ROOT, check, md_table, read

SOURCES = set()


def src(rel):
    """Read a C tree file and remember it as a source."""
    SOURCES.add(rel)
    return read(rel)


# --------------------------------------------------------------------------
# Generic helpers
# --------------------------------------------------------------------------

def strip_c_comments(text):
    """Blank out C comments, keeping newlines so line numbers survive."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        two = text[i:i + 2]
        if two == "/*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(text[i:j])
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def norm(s):
    """Collapse whitespace."""
    return re.sub(r"\s+", " ", s).strip()


def pp_snapshots(text):
    """
    Return, per physical line, the tuple of active preprocessor branches.

    `text` must already have comments removed.  Each entry is the condition
    under which its branch is taken, with every earlier branch of the same
    `#if` chain negated: `#elif E` after `#if C` is `!(C) && (E)`, and the
    `#else` after both is `!(C) && !(E)`.
    """
    lines = text.split("\n")
    snaps = [()] * len(lines)
    stack = []  # each: [earlier branch conditions, current branch]
    i = 0
    while i < len(lines):
        start = i
        logical = lines[i]
        while logical.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            logical = logical.rstrip()[:-1] + " " + lines[i]
        m = re.match(r"\s*#\s*(\w+)\s*(.*)", logical)
        if m:
            d, rest = m.group(1), norm(m.group(2))
            if d == "ifdef":
                stack.append([[f"defined({rest})"], f"defined({rest})"])
            elif d == "ifndef":
                stack.append([[f"!defined({rest})"], f"!defined({rest})"])
            elif d == "if":
                stack.append([[rest], rest])
            elif d == "elif" and stack:
                earlier = stack[-1][0]
                stack[-1][1] = " && ".join(
                    [f"!({c})" for c in earlier] + [f"({rest})"])
                earlier.append(rest)
            elif d == "else" and stack:
                stack[-1][1] = " && ".join(f"!({c})" for c in stack[-1][0])
            elif d == "endif" and stack:
                stack.pop()
        snap = tuple(e[1] for e in stack)
        for k in range(start, i + 1):
            snaps[k] = snap
        i += 1
    return snaps


def line_of(text, pos):
    """Return the 1-based line number of offset pos."""
    return text.count("\n", 0, pos) + 1


def cmake_strip(text):
    """Blank out CMake `#` comments outside quoted strings, keeping newlines."""
    out = []
    for line in text.split("\n"):
        q = False
        cut = len(line)
        k = 0
        while k < len(line):
            ch = line[k]
            if ch == "\\":
                k += 2
                continue
            if ch == '"':
                q = not q
            elif ch == "#" and not q:
                cut = k
                break
            k += 1
        out.append(line[:cut])
    return "\n".join(out)


def cmake_statements(text):
    """Yield (command, [args], start_line) for each CMake command call."""
    text = cmake_strip(text)
    for m in re.finditer(r"^[ \t]*([A-Za-z_]\w*)[ \t]*\(", text, re.MULTILINE):
        i = m.end()
        depth, q, toks, cur, qd = 1, False, [], "", False
        while i < len(text) and depth:
            ch = text[i]
            if q:
                if ch == "\\":
                    cur += text[i:i + 2]
                    i += 2
                    continue
                if ch == '"':
                    q = False
                else:
                    cur += ch
            elif ch == '"':
                q, qd = True, True
            elif ch == "(":
                depth += 1
                cur += ch
            elif ch == ")":
                depth -= 1
                if depth:
                    cur += ch
            elif ch.isspace():
                if cur or qd:
                    toks.append(cur)
                    cur, qd = "", False
            else:
                cur += ch
            i += 1
        if cur or qd:
            toks.append(cur)
        yield m.group(1), toks, line_of(text, m.start())


def split_top_commas(s):
    """Split on commas outside parentheses."""
    parts, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return [norm(p) for p in parts if norm(p)]


# --------------------------------------------------------------------------
# 1. Protocols
# --------------------------------------------------------------------------

def parse_protocols():
    """Build the protocol/scheme records from lib/protocol.[ch]."""
    ph = strip_c_comments(src("lib/protocol.h"))
    pc_raw = src("lib/protocol.c")
    pc = strip_c_comments(pc_raw)
    curl_h = strip_c_comments(src("include/curl/curl.h"))
    version_c = strip_c_comments(src("lib/version.c"))

    ports = {m.group(1): int(m.group(2))
             for m in re.finditer(r"#define PORT_(\w+)\s+(\d+)", ph)}
    protopt = {}
    for m in re.finditer(r"#define (PROTOPT_\w+)\s+\(1 << (\d+)\)", ph):
        protopt[m.group(1)] = int(m.group(2))
    protopt["PROTOPT_NONE"] = None  # value 0, no bit
    check(len(protopt) == len(re.findall(r"#define PROTOPT_\w+", ph)),
          "every PROTOPT_ define parsed")

    public_bits = {m.group(1): int(m.group(2)) for m in re.finditer(
        r"#define CURLPROTO_(\w+)\s+\(1L << (\d+)\)", curl_h)}
    check(len(public_bits) == 30 and sorted(public_bits.values()) == list(range(30)),
          "public CURLPROTO_ bits are 0..29, each once")
    check(public_bits["HTTP"] == 0, "CURLPROTO_HTTP is bit 0 (value 1)")
    internal_bits = {m.group(1): int(m.group(2)) for m in re.finditer(
        r"#define CURLPROTO_(\w+)\s+\(+(?:\(curl_prot_t\))?1(?:L|LL)?\s*<<\s*(\d+)\)", ph)}
    check(sorted(internal_bits) == ["MQTTS", "SOCKS", "WS", "WSS"],
          "internal CURLPROTO_ bits are WS/WSS/MQTTS/SOCKS")
    bit_of = dict(public_bits)
    bit_of.update(internal_bits)

    # Scheme blocks.
    blocks = list(re.finditer(
        r"const struct Curl_scheme Curl_scheme_(\w+) = \{(.*?)\n\};", pc, re.DOTALL))
    declared = re.findall(r"extern const struct Curl_scheme Curl_scheme_(\w+);", ph)
    check(len(blocks) == len(declared) == 30,
          f"30 Curl_scheme definitions == declarations ({len(blocks)}/{len(declared)})")
    check(sorted(b.group(1) for b in blocks) == sorted(declared),
          "scheme definitions match the extern declarations")

    # Implementation definitions.
    impl_defs = {}
    for path in sorted(ROOT.glob("lib/**/*.c")):
        rel = str(path.relative_to(ROOT))
        txt = strip_c_comments(path.read_text(errors="replace"))
        for m in re.finditer(r"^const struct Curl_protocol Curl_protocol_(\w+) = \{", txt, re.MULTILINE):
            impl_defs.setdefault(m.group(1), []).append(
                {"file": rel, "line": line_of(txt, m.start())})
            SOURCES.add(rel)

    schemes = []
    for b in blocks:
        ident, body = b.group(1), b.group(2)
        name = re.search(r'"([a-z0-9]+)"', body).group(1)
        check(ident == name, f"scheme identifier {ident} equals its name {name}")
        # The run pointer: everything between the name and the protocol bit.
        head, tail = body.split("CURLPROTO_", 1)
        tail = "CURLPROTO_" + tail
        run_part = head.split('"' + name + '"', 1)[1]
        impl = re.search(r"&Curl_protocol_(\w+)", run_part)
        cond = None
        m = re.search(r"#\s*(ifdef|ifndef|if)\s+(.*?)\n\s*(?:ZERO_NULL|NULL)", run_part, re.DOTALL)
        if m:
            kind, expr = m.group(1), norm(m.group(2).replace("\\", " "))
            cond = {"ifdef": expr, "ifndef": f"!defined({expr})", "if": expr}[kind]
            if kind == "ifdef":
                cond = f"defined({expr})"
        fields = split_top_commas(tail)
        check(len(fields) == 4, f"scheme {name}: 4 trailing fields, got {len(fields)}")
        protocol, family, flags_expr, defport = fields
        flags = sorted(set(re.findall(r"PROTOPT_\w+", flags_expr)))
        for f in flags:
            check(f in protopt, f"scheme {name}: unknown flag {f}")
        pbit = protocol.removeprefix("CURLPROTO_")
        fbit = family.removeprefix("CURLPROTO_")
        check(pbit in bit_of and fbit in bit_of, f"scheme {name}: unknown protocol bit")
        if defport == "0":
            port = 0
        else:
            check(defport.startswith("PORT_") and defport[5:] in ports,
                  f"scheme {name}: unresolved port {defport}")
            port = ports[defport[5:]]
        impl_name = impl.group(1) if impl else None
        schemes.append({
            "name": name,
            "scheme-def": {"file": "lib/protocol.c", "line": line_of(pc, b.start())},
            "protocol-bit": pbit, "protocol-bit-number": bit_of[pbit],
            "family-bit": fbit, "family-bit-number": bit_of[fbit],
            "bit-visibility": "public" if pbit in public_bits else "internal",
            "default-port": port, "default-port-macro": defport,
            "flags": flags,
            "handler": impl_name,
            "handler-absent-when": cond if (cond or not impl) else None,
            "handler-files": [d["file"] for d in impl_defs.get(impl_name, [])],
            "disable-macros": sorted(set(re.findall(r"CURL_DISABLE_\w+", cond or ""))),
        })
    schemes.sort(key=lambda s: s["name"])

    # Handler references must resolve to definitions.
    for s in schemes:
        if s["handler"]:
            check(s["handler"] in impl_defs, f"handler Curl_protocol_{s['handler']} defined")
    referenced = {s["handler"] for s in schemes if s["handler"]}
    unreferenced = sorted(set(impl_defs) - referenced)
    check(unreferenced == [], f"every Curl_protocol_ definition is referenced: {unreferenced}")
    n_defs = sum(len(v) for v in impl_defs.values())
    check(n_defs == 21, f"21 Curl_protocol definitions (ldap, scp, sftp twice), got {n_defs}")

    # Lookup functions: N_letter_scheme must return only names of length N.
    words = {2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven"}
    reachable = {}
    for n, w in words.items():
        m = re.search(rf"static const struct Curl_scheme \*{w}_letter_scheme\(.*?\n\}}", pc, re.DOTALL)
        check(m is not None, f"{w}_letter_scheme found")
        for r in re.findall(r"&Curl_scheme_(\w+)", m.group(0)):
            reachable[r] = n
    check(sorted(reachable) == sorted(s["name"] for s in schemes),
          "every scheme is reachable from a lookup function")
    for s in schemes:
        check(reachable[s["name"]] == len(s["name"]),
              f"scheme {s['name']} sits in the lookup function for its length")
        s["lookup-function"] = f"{words[reachable[s['name']]]}_letter_scheme"

    # Public bits with no scheme.
    used_bits = {s["protocol-bit"] for s in schemes}
    unmapped = sorted((b for b in public_bits if b not in used_bits),
                      key=lambda b: public_bits[b])
    check(len({s["protocol-bit"] for s in schemes}) == 26,
          "26 distinct protocol bits across the 30 schemes (22 public + 4 internal)")

    # version.c supported_protocols[].
    snaps = pp_snapshots(version_c)
    lines = version_c.split("\n")
    start = next(i for i, l in enumerate(lines) if "supported_protocols[] = {" in l)
    end = next(i for i in range(start, len(lines)) if lines[i].strip() == "NULL")
    listed = []
    for i in range(start, end):
        m = re.match(r'\s*"([a-z0-9]+)",', lines[i])
        if m:
            listed.append({"name": m.group(1), "line": i + 1, "conditions": list(snaps[i])})
    check(len(listed) == len(re.findall(r'^\s*"[a-z0-9]+",', "\n".join(lines[start:end]), re.MULTILINE)),
          "all supported_protocols entries parsed")
    names_listed = [p["name"] for p in listed]
    check(names_listed == sorted(names_listed), "supported_protocols is alphabetical")
    non_socks = sorted(s["name"] for s in schemes if not s["name"].startswith("socks"))
    check(sorted(names_listed) == non_socks and len(non_socks) == 25,
          "version.c protocol list == scheme table minus the 5 socks schemes")

    discrepancies = []
    ldaps = next(s for s in schemes if s["name"] == "ldaps")
    vldaps = next(p for p in listed if p["name"] == "ldaps")
    discrepancies.append({
        "what": "ldaps availability condition differs between lib/protocol.c and lib/version.c",
        "protocol.c": ldaps["handler-absent-when"],
        "version.c": vldaps["conditions"],
        "status": "hypothesis",
    })
    # Same check for every other protocol: scheme says absent-when X; version.c lists under !X.
    for s in schemes:
        p = next((q for q in listed if q["name"] == s["name"]), None)
        if not p or s["name"] == "ldaps":
            continue
        ours = set(re.findall(r"CURL_DISABLE_\w+|USE_SSL|USE_SSH", s["handler-absent-when"] or ""))
        theirs = set(re.findall(r"CURL_DISABLE_\w+|USE_SSL|USE_SSH", " ".join(p["conditions"])))
        if ours != theirs:
            discrepancies.append({
                "what": f"{s['name']}: macro sets differ between protocol.c and version.c",
                "protocol.c": sorted(ours), "version.c": sorted(theirs), "status": "hypothesis"})

    # CMake's own protocol list (curl_add_if).
    cm = src("CMakeLists.txt")
    groups = []
    for cmd, args, ln in cmake_statements(cm):
        if cmd == "set" and args[:2] == ["_items", ""]:
            groups.append([])
        elif cmd == "curl_add_if":
            groups[-1].append({"name": args[0], "condition": norm(" ".join(args[1:])), "line": ln})
    check(len(groups) == 3, f"CMake has 3 curl_add_if groups (protocols, features, ssl): {len(groups)}")
    cm_protocols, cm_features, cm_ssl = groups
    check(len(cm_protocols) == len(re.findall(
        r'^curl_add_if\("(?:HTTP|HTTPS|FTP|FTPS|FILE|TELNET|LDAP|LDAPS|DICT|TFTP|GOPHER|GOPHERS|'
        r'POP3|POP3S|IMAP|IMAPS|SMTP|SMTPS|SCP|SFTP|IPFS|IPNS|RTSP|MQTT|MQTTS|WS|WSS)"',
        cm, re.MULTILINE)) == 27, "CMake protocol list has 27 curl_add_if entries")
    cm_names = sorted(p["name"].lower() for p in cm_protocols)
    tool_only = ["ipfs", "ipns"]
    check(sorted(set(cm_names) - set(tool_only)) == sorted(names_listed),
          "CMake protocol list minus ipfs/ipns == version.c protocol list")
    return {
        "schemes": schemes,
        "port-macros": ports,
        "protopt-bits": dict(sorted(protopt.items())),
        "curlproto-public-bits": public_bits,
        "curlproto-internal-bits": internal_bits,
        "curlproto-unmapped-public-bits": unmapped,
        "handler-definitions": impl_defs,
        "version-c-protocol-list": listed,
        "cmake-protocol-list": cm_protocols,
        "tool-only-pseudo-protocols": [
            {"name": n, "file": "src/tool_ipfs.c", "disable-macro": "CURL_DISABLE_IPFS",
             "note": "not a libcurl scheme; src/tool_help.c prints it in Protocols: when http is built in"}
            for n in tool_only],
        "discrepancies": discrepancies,
    }, cm_features, cm_ssl


# --------------------------------------------------------------------------
# 2. Features
# --------------------------------------------------------------------------

def parse_features(cm_features, protocols):
    """Build the curl_version_info feature records and the test vocabulary."""
    vc = strip_c_comments(src("lib/version.c"))
    curl_h = strip_c_comments(src("include/curl/curl.h"))
    snaps = pp_snapshots(vc)

    bits = {m.group(1): int(m.group(2)) for m in re.finditer(
        r"#define CURL_VERSION_(\w+)\s+\(1<<(\d+)\)", curl_h)}
    check(len(bits) == 31 and sorted(bits.values()) == list(range(31)),
          "31 CURL_VERSION_ bits, 0..30")
    check(bits["SSL"] == 2, "CURL_VERSION_SSL is bit 2")

    feats = []
    for m in re.finditer(r'\bFEATURE\("([^"]+)",\s*(\w+),\s*(\w+)\)', vc):
        ln = line_of(vc, m.start())
        name, present, mask = m.groups()
        if mask != "0":
            check(mask in {f"CURL_VERSION_{b}" for b in bits}, f"feature {name}: undefined {mask}")
        feats.append({
            "name": name, "line": ln, "conditions": list(snaps[ln - 1]),
            "bit": mask.removeprefix("CURL_VERSION_") if mask != "0" else None,
            "bit-number": bits[mask.removeprefix("CURL_VERSION_")] if mask != "0" else None,
            "runtime-check": present if present != "NULL" else None,
            "source": "lib/version.c",
        })
    raw_count = len(re.findall(r'\bFEATURE\("', vc))
    check(len(feats) == raw_count and raw_count > 30,
          f"every FEATURE(\" line parsed ({len(feats)}/{raw_count})")
    names = [f["name"] for f in feats]
    check(len(set(names)) == len(names), "feature names unique")
    check("SSL" in names and "HTTP2" in names and "alt-svc" in names, "well-known features present")
    ssl = next(f for f in feats if f["name"] == "SSL")
    check(ssl["bit"] == "SSL" and ssl["conditions"] == ["defined(USE_SSL)"], "SSL feature row")

    # Extras appended by the tool when printing the Features: line.
    th_raw = src("src/tool_help.c")
    th = strip_c_comments(th_raw)
    th_snaps = pp_snapshots(th)
    extras = []
    for m in re.finditer(r'feat_ext\[feat_ext_count\+\+\] = "([^"]+)";', th):
        ln = line_of(th, m.start())
        extras.append({"name": m.group(1), "line": ln, "conditions": list(th_snaps[ln - 1]),
                       "bit": None, "bit-number": None, "runtime-check": None,
                       "source": "src/tool_help.c"})
    check([e["name"] for e in extras] == ["CAcert", "global-mem-debug"], "two tool-added features")

    used_bits = {f["bit"] for f in feats if f["bit"]}
    unused = sorted((b for b in bits if b not in used_bits), key=lambda b: bits[b])
    debug_or = re.search(r"features \|= CURL_VERSION_CURLDEBUG", vc)
    check(debug_or is not None, "CURLDEBUG bit is OR'd in separately")

    # docs/libcurl/curl_version_info.md cross-check.
    doc = src("docs/libcurl/curl_version_info.md")
    doc_names = re.findall(r"^## `([^`]+)`", doc, re.MULTILINE)
    all_printed = set(names) | {e["name"] for e in extras}
    table_only = sorted(set(names) - set(doc_names))
    doc_only = sorted(set(doc_names) - set(names))

    # CMake feature list cross-check.
    cm_names = sorted(f["name"] for f in cm_features)
    check(len(cm_features) >= 25, "CMake feature list parsed")
    cm_only = sorted(set(cm_names) - all_printed)
    c_only = sorted(all_printed - set(cm_names))

    # Test-gating vocabulary.
    rt = src("tests/runtests.pl")
    rt_regex = {}
    rt_assign = {}
    for i, line in enumerate(rt.split("\n"), 1):
        m = re.search(r'\$feature\{"([^"]+)"\}\s*=\s*\$feat\s*=~\s*/(.+?)/(i?);', line)
        if m:
            rt_regex[m.group(1)] = {"regex": m.group(2), "ignore-case": bool(m.group(3)), "line": i}
            continue
        m = re.search(r'\$feature\{"([^"]+)"\}\s*=', line)
        if m:
            rt_assign.setdefault(m.group(1), i)
    ci = strip_c_comments(src("src/curlinfo.c"))
    ci_snaps = pp_snapshots(ci)
    curlinfo = []
    for m in re.finditer(
            r'"([^"]+): "\s*#\s*(ifdef|ifndef|if)\s+((?:[^\n]|\\\n)*?)\n\s*"(ON|OFF)"\s*\n\s*#\s*else\s*\n\s*"(ON|OFF)"',
            ci):
        kind, expr = m.group(2), norm(m.group(3).replace("\\", " "))
        if kind == "ifdef":
            expr = f"defined({expr})"
        elif kind == "ifndef":
            expr = f"!defined({expr})"
        curlinfo.append({"name": m.group(1), "line": line_of(ci, m.start()),
                         "on-when": expr if m.group(4) == "ON" else f"!({expr})"})
    check(len(curlinfo) == len(re.findall(r'^\s*"[^"]+: "\s*$', ci, re.MULTILINE)) > 30,
          f"curlinfo.c entries parsed == grep count ({len(curlinfo)})")
    check("cookies" in {c["name"] for c in curlinfo}, "curlinfo has cookies")
    del ci_snaps

    # Printable protocol names for the protocols-as-features rule.
    protos = sorted({p["name"] for p in protocols["version-c-protocol-list"]} | {"ipfs", "ipns"})
    proto_feats = set(protos)
    proto_feats |= {f"{p}-ipv6" for p in protos} | {f"{p}-unix" for p in protos}
    proto_feats |= {"http-proxy", "https-mtls", "none", "http/2", "http/3", "https-proxy"}

    # Used by tests.
    used = {}
    n_files = n_blocks = n_tags = 0
    for path in sorted((ROOT / "tests/data").glob("test[0-9]*")):
        txt = path.read_text(errors="replace")
        if "<features>" not in txt:
            continue
        n_files += 1
        n_tags += txt.count("<features>")
        for m in re.finditer(r"<features>\n(.*?)</features>", txt, re.DOTALL):
            n_blocks += 1
            for ln in m.group(1).splitlines():
                ln = ln.strip().replace(" ", "")
                if ln:
                    used.setdefault(ln.removeprefix("!"), set()).add(path.name.removeprefix("test"))
    SOURCES.add("tests/data")
    SOURCES.add("tests/runtests.pl")
    SOURCES.add("src/curlinfo.c")
    check(n_blocks == n_tags and n_files > 1000,
          f"every <features> tag opens a well-formed block ({n_blocks}/{n_tags}) in {n_files} files")

    def origin(n):
        if n in rt_regex:
            r = rt_regex[n]
            flags = re.IGNORECASE if r["ignore-case"] else 0
            ms = sorted(p for p in all_printed if re.search(r["regex"], p, flags))
            return {"kind": "features-line-regex", "line": r["line"], "regex": r["regex"],
                    "ignore-case": r["ignore-case"], "matches-printed-features": ms}
        if n in {c["name"] for c in curlinfo}:
            return {"kind": "src/curlinfo.c"}
        if n in rt_assign:
            return {"kind": "runtests.pl-assignment", "line": rt_assign[n]}
        if n in proto_feats:
            return {"kind": "protocol-as-feature"}
        if n in all_printed:
            return {"kind": "printed-feature-name-used-directly"}
        return None

    vocab = []
    unknown = []
    for n in sorted(used):
        o = origin(n)
        if o is None:
            unknown.append(n)
            continue
        vocab.append({"name": n, "tests": len(used[n]), "origin": o})
    check(not unknown, f"every test feature name has an origin; unknown: {unknown}")
    check(len(used) > 80, f"test feature vocabulary size {len(used)}")
    dead = sorted(f for f, r in rt_regex.items() if not origin(f)["matches-printed-features"])

    return {
        "version-bits": bits,
        "features": sorted(feats, key=lambda f: f["name"].lower()),
        "tool-added-features": extras,
        "bits-not-in-table": unused,
        "curldebug-or-in-separately": True,
        "docs-headings": doc_names,
        "docs-missing-from-table": doc_only,
        "table-missing-from-docs": table_only,
        "cmake-feature-list": sorted(cm_features, key=lambda f: f["name"].lower()),
        "cmake-only-feature-names": cm_only,
        "printed-only-feature-names": c_only,
        "curlinfo-entries": curlinfo,
        "runtests-features-line-regexes": rt_regex,
        "runtests-assignments": rt_assign,
        "runtests-regexes-matching-no-printed-feature": dead,
        "test-feature-vocabulary": vocab,
        "test-files-with-features": n_files,
        "test-feature-blocks": n_blocks,
    }


# --------------------------------------------------------------------------
# 3. Build options
# --------------------------------------------------------------------------

def parse_cmake_options():
    """Parse CMake options with their enclosing if() context."""
    files = ["CMakeLists.txt"] + sorted(
        str(p.relative_to(ROOT)) for p in (ROOT / "CMake").glob("*.cmake")) + [
        "CMake/curl-config.in.cmake"]
    files = sorted(set(files))
    opts = []
    skipped = []
    cache_tokens = 0
    for rel in files:
        text = src(rel)
        cache_tokens += len(re.findall(r"^[ \t]*set\([^()]*?\bCACHE\b", cmake_strip(text), re.MULTILINE | re.DOTALL))
        stack = []
        for cmd, args, ln in cmake_statements(text):
            lc = cmd.lower()
            if lc == "if":
                stack.append(norm(" ".join(args)))
            elif lc == "elseif" and stack:
                stack[-1] = "elseif " + norm(" ".join(args))
            elif lc == "else" and stack:
                stack[-1] = "else"
            elif lc == "endif" and stack:
                stack.pop()
            kind = None
            if lc == "option":
                kind, name, desc, default, dep = "option", args[0], args[1], args[2] if len(args) > 2 else "", None
            elif lc == "cmake_dependent_option":
                kind, name, desc, default, dep = ("cmake_dependent_option", args[0], args[1],
                                                  args[2], norm(" ".join(args[3:])))
            elif lc == "curl_dependency_option":
                kind, name, desc, default, dep = ("curl_dependency_option", args[0],
                                                  f"Build curl with {args[2]} support (AUTO, ON or OFF)",
                                                  "AUTO", f"find_package({args[1]})")
            elif lc == "set" and "CACHE" in args:
                i = args.index("CACHE")
                kind, name = "set-cache", args[0]
                default = args[1] if i > 1 else ""
                desc = args[i + 2] if len(args) > i + 2 else ""
                dep = args[i + 1] if len(args) > i + 1 else None
            if kind is None:
                continue
            if "$" in name:
                skipped.append({"file": rel, "line": ln, "name": name,
                                "reason": "templated name inside a macro body"})
                continue
            opts.append({
                "name": name, "kind": kind, "file": rel, "line": ln,
                "default": default, "description": desc, "depends": dep,
                "enclosing-conditions": list(stack),
            })
    n_grep = sum(len(re.findall(
        r"^\s*(?:option|cmake_dependent_option|curl_dependency_option)\(", cmake_strip(read(f)), re.MULTILINE))
        for f in files)
    n_decl = sum(1 for o in opts if o["kind"] != "set-cache")
    # curl_dependency_option's own macro definition is not a call to count.
    check(n_decl == n_grep,
          f"CMake option/dependent/dependency calls parsed == grep ({n_decl}/{n_grep})")
    n_cache = sum(1 for o in opts if o["kind"] == "set-cache") + sum(
        1 for s in skipped)
    check(n_cache == cache_tokens, f"CMake set(... CACHE) parsed == independent regex count ({n_cache}/{cache_tokens})")
    names = {o["name"] for o in opts}
    for want in ("CURL_USE_OPENSSL", "ENABLE_DEBUG", "CURL_DISABLE_HTTP", "USE_NGHTTP2",
                 "CURL_ZLIB", "CURL_USE_SCHANNEL"):
        check(want in names, f"CMake option {want} present")
    return sorted(opts, key=lambda o: (o["name"], o["file"], o["line"])), skipped


def m4_strip(text):
    """Blank out m4 `dnl` comments and whole-line `#` comments, keeping newlines."""
    text = re.sub(r"\bdnl\b[^\n]*", lambda m: " " * len(m.group(0)), text)
    return re.sub(r"^[ \t]*#[^\n]*", lambda m: " " * len(m.group(0)), text, flags=re.MULTILINE)


def parse_configure_options():
    """Parse AC_ARG_ENABLE/AC_ARG_WITH invocations and their help switches."""
    files = ["configure.ac", "acinclude.m4"] + sorted(
        str(p.relative_to(ROOT)) for p in (ROOT / "m4").glob("*.m4"))
    out = []
    skipped = []
    help_total = 0
    for rel in files:
        text = m4_strip(src(rel))
        help_total += len(re.findall(r"AS_HELP_STRING|AC_HELP_STRING", text))
        for m in re.finditer(r"AC_ARG_(ENABLE|WITH)\b", text):
            if text[m.end():m.end() + 1] != "(":
                skipped.append({"file": rel, "line": line_of(text, m.start()),
                                "reason": "AC_REQUIRE reference, not an invocation"})
                continue
            i = m.end() + 1
            depth = 1
            while i < len(text) and depth:
                depth += {"(": 1, ")": -1}.get(text[i], 0)
                i += 1
            span = text[m.start():i]
            name = re.match(r"AC_ARG_\w+\(\s*\[?([\w.-]+)", span).group(1)
            helps = []
            span2 = span.replace("@<:@", "{").replace("@:>@", "}")
            for h in re.finditer(
                    r"(?:AS|AC)_HELP_STRING\(\s*\[?(--[^\],\s]+)\]?\s*,\s*\[?((?:[^\[\]()]|\([^)]*\))*)",
                    span2):
                sw = h.group(1).replace("{", "[").replace("}", "]")
                helps.append({"switch": sw, "name": re.match(r"--[\w-]+", sw).group(0),
                              "description": norm(h.group(2).replace("\\\n", " "))})
            out.append({"kind": m.group(1).lower(), "name": name, "file": rel,
                        "line": line_of(text, m.start()), "switches": helps,
                        "rejected-at-configure-time": not helps and "AC_MSG_ERROR" in span})
    n_inv = len(out)
    n_grep = sum(len(re.findall(r"AC_ARG_(?:ENABLE|WITH)\(", m4_strip(read(f)))) for f in files)
    check(n_inv == n_grep and n_inv >= 100, f"AC_ARG invocations parsed == grep ({n_inv}/{n_grep})")
    n_help = sum(len(o["switches"]) for o in out)
    check(n_help == help_total, f"every help string attributed to an invocation ({n_help}/{help_total})")
    for o in out:
        check(o["switches"] or o["rejected-at-configure-time"],
              f"{o['file']}:{o['line']} {o['name']}: has a help switch or rejects the option")
    names = {o["name"] for o in out}
    check({"openssl", "debug", "ares"} <= names, "configure has openssl/debug/ares")
    allsw = {s["name"] for o in out for s in o["switches"]}
    check("--with-openssl" in allsw and "--enable-debug" in allsw, "well-known switches present")
    return sorted(out, key=lambda o: (o["name"], o["file"], o["line"])), skipped


def strip_code_files():
    """Yield (relpath, comment-stripped text) for lib/, src/ and include/curl."""
    for pat in ("lib/**/*.[ch]", "src/**/*.[ch]", "include/curl/*.h"):
        for p in sorted(ROOT.glob(pat)):
            rel = str(p.relative_to(ROOT))
            yield rel, strip_c_comments(p.read_text(errors="replace"))


def parse_disable_macros(cmake_opts, ac_text_cache):
    """Cross-check CURL_DISABLE_* across the docs, code, CMake and configure."""
    doc = src("docs/CURL-DISABLE.md")
    documented = re.findall(r"^## `(CURL_DISABLE_\w+)`", doc, re.MULTILINE)
    check(len(documented) == len(re.findall(r"^## ", doc, re.MULTILINE)),
          "every CURL-DISABLE.md section is a CURL_DISABLE_ heading")
    check(len(set(documented)) == len(documented), "CURL-DISABLE.md headings unique")
    in_code = {}
    n_files = 0
    for rel, txt in strip_code_files():
        n_files += 1
        for m in re.finditer(r"\bCURL_DISABLE_\w+", txt):
            in_code.setdefault(m.group(0), set()).add(rel)
    check(n_files > 300, f"scanned {n_files} code files")
    cm_opts = {o["name"] for o in cmake_opts if o["name"].startswith("CURL_DISABLE_")}
    cmakedefine = set(re.findall(r"#cmakedefine\s+(CURL_DISABLE_\w+)", src("lib/curl_config-cmake.h.in")))
    cfg = set()
    for txt in ac_text_cache:
        cfg |= set(re.findall(r"AC_DEFINE\(\s*\[?(CURL_DISABLE_\w+)", txt))
    check("CURL_DISABLE_HTTP" in documented and "CURL_DISABLE_HTTP" in in_code
          and "CURL_DISABLE_HTTP" in cm_opts and "CURL_DISABLE_HTTP" in cfg,
          "CURL_DISABLE_HTTP in every source")
    universe = sorted(set(documented) | set(in_code) | cm_opts | cmakedefine | cfg)
    rows = [{
        "name": n, "documented": n in documented,
        "used-in-code-files": len(in_code.get(n, ())),
        "code-files": sorted(in_code.get(n, ())) if len(in_code.get(n, ())) <= 6 else "many",
        "cmake-option": n in cm_opts, "cmakedefine": n in cmakedefine,
        "configure-define": n in cfg,
    } for n in universe]
    mism = {
        "documented-not-used-in-code": sorted(set(documented) - set(in_code)),
        "used-in-code-not-documented": sorted(set(in_code) - set(documented)),
        "documented-not-cmake-option": sorted(set(documented) - cm_opts),
        "cmake-option-not-documented": sorted(cm_opts - set(documented)),
        "documented-not-in-configure": sorted(set(documented) - cfg),
        "configure-define-not-documented": sorted(cfg - set(documented)),
        "cmake-option-without-cmakedefine": sorted(cm_opts - cmakedefine),
        "cmakedefine-without-cmake-option": sorted(cmakedefine - cm_opts),
        "used-in-code-no-build-system-define": sorted(set(in_code) - cmakedefine - cfg),
    }
    return {"documented": documented, "macros": rows, "mismatches": mism,
            "code-files-scanned": n_files}


# --------------------------------------------------------------------------
# 4. Backends
# --------------------------------------------------------------------------

STD_HEADERS = {
    "stdio.h", "stdlib.h", "string.h", "errno.h", "limits.h", "stdarg.h", "stddef.h",
    "time.h", "stdint.h", "stdbool.h", "ctype.h", "assert.h", "inttypes.h", "signal.h",
    "setjmp.h", "locale.h", "math.h", "stdatomic.h",
}


def tls_backends(cm_ssl):
    """Extract the TLS backend table mechanically from lib/vtls."""
    vtls = strip_c_comments(src("lib/vtls/vtls.c"))
    curl_h = strip_c_comments(src("include/curl/curl.h"))
    vs = pp_snapshots(vtls)
    vl = vtls.split("\n")
    s = next(i for i, l in enumerate(vl) if "available_backends[] = {" in l)
    e = next(i for i in range(s, len(vl)) if vl[i].strip() == "NULL")
    avail = []
    for i in range(s, e):
        m = re.match(r"\s*&Curl_ssl_(\w+),", vl[i])
        if m:
            avail.append({"symbol": m.group(1), "index": len(avail), "line": i + 1,
                          "conditions": list(vs[i])})
    # Default selection chain.
    s2 = next(i for i, l in enumerate(vl) if l.startswith("const struct Curl_ssl *Curl_ssl ="))
    chain = []
    for i in range(s2, s2 + 20):
        m = re.search(r"&Curl_ssl_(\w+);", vl[i])
        if m:
            cond = vs[i][-1] if vs[i] else "(none)"
            chain.append({"symbol": m.group(1), "condition": cond})
        if re.search(r"#\s*endif", vl[i]):
            break

    enum = [{"name": m.group(1), "id": int(m.group(4)), "deprecated-since": m.group(3)}
            for m in re.finditer(
                r"CURLSSLBACKEND_(\w+?)\s*(CURL_DEPRECATED\(([^,]+),[^)]*\))?\s*=\s*(\d+)", curl_h)]
    enum_ids = {e["name"]: e["id"] for e in enum}
    check(len(enum) == 15 and enum_ids["OPENSSL"] == 1 and enum_ids["RUSTLS"] == 14,
          f"CURLSSLBACKEND enum has 15 members, got {len(enum)}")
    aliases = re.findall(r"#define CURLSSLBACKEND_(\w+) CURLSSLBACKEND_(\w+)", curl_h)

    # Backend definitions.
    defs = []
    for p in sorted(ROOT.glob("lib/vtls/*.c")):
        rel = str(p.relative_to(ROOT))
        txt = strip_c_comments(p.read_text(errors="replace"))
        m = re.search(r"^const struct Curl_ssl Curl_ssl_(\w+) = \{", txt, re.MULTILINE)
        if not m:
            continue
        SOURCES.add(rel)
        snaps = pp_snapshots(txt)
        start = line_of(txt, m.start())
        base = snaps[start - 1]
        body = txt[m.end():]
        body = body[:body.index("sizeof(")]
        info = re.search(r"\{\s*CURLSSLBACKEND_(\w+),\s*\"(\w+)\"\s*\}", body)
        flags = []
        for fm in re.finditer(r"SSLSUPP_\w+", body):
            ln = start + body[:fm.start()].count("\n")
            conds = [c for c in snaps[ln - 1] if c not in base]
            flags.append({"flag": fm.group(0), "conditions": conds})
        defs.append({
            "symbol": m.group(1), "file": rel, "line": start,
            "enum": info.group(1), "id": enum_ids[info.group(1)], "name": info.group(2),
            "capabilities": flags,
        })
    names_avail = sorted(a["symbol"] for a in avail)
    names_defs = sorted(d["symbol"] for d in defs)
    check(names_avail == names_defs and len(avail) == 6,
          f"available_backends == Curl_ssl definitions ({names_avail} vs {names_defs})")
    check(sorted(c["symbol"] for c in chain) == sorted(names_avail + ["multi"]),
          "default selection chain covers every backend plus multi")
    supp = {m.group(1): int(m.group(2)) for m in re.finditer(
        r"#define (SSLSUPP_\w+)\s+\(1 << (\d+)\)", read("lib/vtls/vtls.h"))}
    SOURCES.add("lib/vtls/vtls.h")
    for d in defs:
        for f in d["capabilities"]:
            check(f["flag"] in supp, f"{d['name']}: unknown {f['flag']}")
    check(any(d["name"] == "openssl" and d["id"] == 1 for d in defs), "openssl backend id 1")
    cm_names = sorted(c["name"].lower() for c in cm_ssl if "$" not in c["name"])
    code_names = sorted(d["name"] for d in defs if d["name"] != "openssl")
    check(cm_names == code_names,
          f"CMake SSL backend list (minus openssl) == Curl_ssl names: {cm_names} / {code_names}")
    return {"cmake-ssl-backend-list": cm_ssl, "available-backends": avail, "backend-definitions": defs,
            "default-selection-chain": chain, "enum": enum, "enum-aliases": aliases,
            "sslsupp-bits": supp}


# category, name, files, library, build macro, cmake option, configure switch, notes
BACKENDS = [
    # TLS
    ("tls", "openssl", ["lib/vtls/openssl.c"], "OpenSSL (and forks: LibreSSL, BoringSSL, AWS-LC, quictls)", "USE_OPENSSL", "CURL_USE_OPENSSL", "--with-openssl", ""),
    ("tls", "gnutls", ["lib/vtls/gtls.c"], "GnuTLS (+ nettle)", "USE_GNUTLS", "CURL_USE_GNUTLS", "--with-gnutls", ""),
    ("tls", "mbedtls", ["lib/vtls/mbedtls.c"], "Mbed TLS", "USE_MBEDTLS", "CURL_USE_MBEDTLS", "--with-mbedtls", ""),
    ("tls", "wolfssl", ["lib/vtls/wolfssl.c"], "wolfSSL", "USE_WOLFSSL", "CURL_USE_WOLFSSL", "--with-wolfssl", ""),
    ("tls", "rustls", ["lib/vtls/rustls.c"], "rustls-ffi", "USE_RUSTLS", "CURL_USE_RUSTLS", "--with-rustls", "listed as EXPERIMENTAL"),
    ("tls", "schannel", ["lib/vtls/schannel.c", "lib/vtls/schannel_verify.c"], "Windows Schannel (SSPI)", "USE_SCHANNEL", "CURL_USE_SCHANNEL", "--with-schannel", ""),
    ("tls-support", "apple-sectrust", ["lib/vtls/apple.c"], "Apple Security.framework (certificate verification only; not a Curl_ssl backend)", "USE_APPLE_SECTRUST", "USE_APPLE_SECTRUST", "--with-apple-sectrust", "works with OpenSSL or GnuTLS"),
    ("tls-support", "cipher-suite-names", ["lib/vtls/cipher_suite.c"], "none (table)", "USE_MBEDTLS || USE_RUSTLS", None, None, ""),
    ("tls-support", "hostcheck", ["lib/vtls/hostcheck.c"], "none", "USE_OPENSSL || USE_SCHANNEL", None, None, ""),
    ("tls-support", "keylog", ["lib/vtls/keylog.c"], "none (SSLKEYLOGFILE writer)", "USE_OPENSSL || USE_GNUTLS || USE_WOLFSSL ...", None, None, ""),
    ("tls-support", "x509asn1", ["lib/vtls/x509asn1.c"], "none (certinfo ASN.1 parser)", "USE_GNUTLS || USE_WOLFSSL || USE_SCHANNEL ...", None, None, ""),
    ("tls-support", "session-cache", ["lib/vtls/vtls_scache.c"], "none", "USE_SSL", None, None, ""),
    ("tls-support", "session-export", ["lib/vtls/vtls_spack.c"], "none", "USE_SSL && USE_SSLS_EXPORT", "USE_SSLS_EXPORT", "--enable-ssls-export", "EXPERIMENTAL"),
    ("tls-support", "tls-config", ["lib/vtls/vtls_config.c"], "none", "USE_SSL (ECH parts: USE_ECH)", "USE_ECH", "--enable-ech", "ECH is EXPERIMENTAL"),
    ("tls-support", "vtls-core", ["lib/vtls/vtls.c"], "none", "USE_SSL", "CURL_ENABLE_SSL", "--with-ssl", ""),
    # QUIC
    ("quic", "ngtcp2+nghttp3", ["lib/vquic/cf-ngtcp2.c", "lib/vquic/cf-ngtcp2-cmn.c"], "ngtcp2 + nghttp3 (with a ngtcp2_crypto_* TLS glue: ossl/quictls/boringssl/gnutls/wolfssl)", "USE_NGTCP2 && USE_NGHTTP3", "USE_NGTCP2", "--with-ngtcp2", ""),
    ("quic", "quiche", ["lib/vquic/cf-quiche.c"], "quiche (+ OpenSSL)", "USE_QUICHE", "USE_QUICHE", "--with-quiche", "EXPERIMENTAL"),
    ("quic", "vquic-core", ["lib/vquic/vquic.c"], "none", "USE_HTTP3", None, None, ""),
    ("quic", "vquic-tls", ["lib/vquic/vquic-tls.c"], "TLS backend glue for QUIC (OpenSSL, GnuTLS, wolfSSL)", "USE_HTTP3", None, None, ""),
    ("quic", "capsule", ["lib/vquic/capsule.c", "lib/vquic/cf-capsule.c"], "none (HTTP capsule protocol for CONNECT-UDP)", "!CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP", None, None, ""),
    ("quic", "ngtcp2-proxy", ["lib/vquic/cf-ngtcp2-proxy.c"], "ngtcp2 + nghttp3 (HTTP/3 proxy)", "USE_PROXY_HTTP3", "USE_PROXY_HTTP3", "--enable-proxy-http3", "EXPERIMENTAL"),
    # SSH
    ("ssh", "libssh2", ["lib/vssh/libssh2.c"], "libssh2", "USE_LIBSSH2", "CURL_USE_LIBSSH2", "--with-libssh2", ""),
    ("ssh", "libssh", ["lib/vssh/libssh.c"], "libssh", "USE_LIBSSH", "CURL_USE_LIBSSH", "--with-libssh", ""),
    ("ssh", "vssh-core", ["lib/vssh/vssh.c"], "none", "USE_SSH", None, None, ""),
    # SASL / auth
    ("auth", "sasl-cleartext", ["lib/vauth/cleartext.c"], "none", "!CURL_DISABLE_IMAP || !CURL_DISABLE_SMTP || ...", None, None, ""),
    ("auth", "cram-md5", ["lib/vauth/cram.c"], "none", "!CURL_DISABLE_DIGEST_AUTH", "CURL_DISABLE_DIGEST_AUTH", None, ""),
    ("auth", "digest", ["lib/vauth/digest.c"], "none (local or TLS-library hashes)", "!CURL_DISABLE_DIGEST_AUTH", "CURL_DISABLE_DIGEST_AUTH", None, ""),
    ("auth", "digest-sspi", ["lib/vauth/digest_sspi.c"], "Windows SSPI", "USE_WINDOWS_SSPI && !CURL_DISABLE_DIGEST_AUTH", "CURL_WINDOWS_SSPI", None, ""),
    ("auth", "gsasl", ["lib/vauth/gsasl.c"], "libgsasl", "USE_GSASL", "CURL_USE_GSASL", "--with-libgsasl", ""),
    ("auth", "kerberos-gssapi", ["lib/vauth/krb5_gssapi.c"], "GSS-API library (MIT Kerberos, GNU GSS, Apple GSS)", "HAVE_GSSAPI && USE_KERBEROS5", "CURL_USE_GSSAPI", "--with-gssapi", ""),
    ("auth", "kerberos-sspi", ["lib/vauth/krb5_sspi.c"], "Windows SSPI", "USE_WINDOWS_SSPI && USE_KERBEROS5", "CURL_WINDOWS_SSPI", None, ""),
    ("auth", "ntlm", ["lib/vauth/ntlm.c", "lib/curl_ntlm_core.c"], "TLS/crypto library DES+MD (OpenSSL, GnuTLS, mbedTLS, wolfSSL, Win32 crypto)", "USE_NTLM && !USE_WINDOWS_SSPI", "CURL_ENABLE_NTLM", "--enable-ntlm", "DEPRECATE.md schedules NTLM removal"),
    ("auth", "ntlm-sspi", ["lib/vauth/ntlm_sspi.c"], "Windows SSPI", "USE_WINDOWS_SSPI && USE_NTLM", "CURL_WINDOWS_SSPI", None, ""),
    ("auth", "oauth2", ["lib/vauth/oauth2.c"], "none", "!CURL_DISABLE_IMAP || !CURL_DISABLE_SMTP || ...", None, None, ""),
    ("auth", "spnego-gssapi", ["lib/vauth/spnego_gssapi.c"], "GSS-API library", "HAVE_GSSAPI && USE_SPNEGO", "CURL_USE_GSSAPI", "--with-gssapi", ""),
    ("auth", "spnego-sspi", ["lib/vauth/spnego_sspi.c"], "Windows SSPI", "USE_WINDOWS_SSPI && USE_SPNEGO", "CURL_WINDOWS_SSPI", None, ""),
    ("auth", "vauth-core", ["lib/vauth/vauth.c"], "none", "(unguarded)", None, None, ""),
    ("auth", "gssapi-helpers", ["lib/curl_gssapi.c"], "GSS-API library", "HAVE_GSSAPI", "CURL_USE_GSSAPI", "--with-gssapi", ""),
    ("auth", "sspi-helpers", ["lib/curl_sspi.c"], "Windows SSPI", "USE_WINDOWS_SSPI", "CURL_WINDOWS_SSPI", None, ""),
    ("auth", "socks-gssapi", ["lib/socks_gssapi.c"], "GSS-API library", "HAVE_GSSAPI && !CURL_DISABLE_PROXY", "CURL_USE_GSSAPI", "--with-gssapi", ""),
    ("auth", "socks-sspi", ["lib/socks_sspi.c"], "Windows SSPI", "USE_WINDOWS_SSPI && !CURL_DISABLE_PROXY", "CURL_WINDOWS_SSPI", None, ""),
    # Resolvers
    ("resolver", "ares", ["lib/vdns/asyn-ares.c"], "c-ares", "USE_RESOLV_ARES", "ENABLE_ARES", "--enable-ares", ""),
    ("resolver", "threaded", ["lib/vdns/asyn-thrdd.c", "lib/thrdpool.c"], "none (POSIX threads or Windows threads)", "USE_RESOLV_THREADED", "ENABLE_THREADED_RESOLVER", "--enable-threaded-resolver", "also hosts the c-ares-assisted HTTPS-RR path"),
    ("resolver", "async-base", ["lib/vdns/asyn-base.c"], "c-ares (optional)", "(unguarded)", None, None, ""),
    ("resolver", "sync-ipv4", ["lib/vdns/hostip4.c"], "libc gethostbyname/getaddrinfo", "CURLRES_IPV4", None, None, ""),
    ("resolver", "sync-ipv6", ["lib/vdns/hostip6.c"], "libc getaddrinfo", "CURLRES_IPV6", "ENABLE_IPV6", "--enable-ipv6", ""),
    ("resolver", "dns-cache", ["lib/vdns/dnscache.c", "lib/vdns/hostip.c"], "none", "(unguarded)", None, None, ""),
    ("resolver", "doh", ["lib/vdns/doh.c"], "none (DNS-over-HTTPS over libcurl itself)", "!CURL_DISABLE_DOH", "CURL_DISABLE_DOH", None, ""),
    ("resolver", "httpsrr", ["lib/vdns/httpsrr.c"], "c-ares or DoH", "USE_HTTPSRR", "USE_HTTPSRR", "--enable-httpsrr", "EXPERIMENTAL"),
    ("resolver", "dns-connect-filter", ["lib/vdns/cf-dns.c"], "none", "(unguarded)", None, None, ""),
    # HTTP/2
    ("http2", "nghttp2", ["lib/http2.c"], "nghttp2", "USE_NGHTTP2 (USE_HTTP2)", "USE_NGHTTP2", "--with-nghttp2", ""),
    ("http2", "nghttp2-proxy", ["lib/cf-h2-proxy.c"], "nghttp2", "USE_NGHTTP2 && !CURL_DISABLE_PROXY", "USE_NGHTTP2", "--with-nghttp2", ""),
    # Compression
    ("compression", "zlib", ["lib/content_encoding.c"], "zlib", "HAVE_LIBZ", "CURL_ZLIB", "--with-zlib", "gzip/deflate"),
    ("compression", "brotli", ["lib/content_encoding.c"], "brotli (decoder)", "HAVE_BROTLI", "CURL_BROTLI", "--with-brotli", ""),
    ("compression", "zstd", ["lib/content_encoding.c"], "zstd", "HAVE_ZSTD", "CURL_ZSTD", "--with-zstd", ""),
    # IDN / PSL
    ("idn", "libidn2", ["lib/idn.c"], "libidn2", "USE_LIBIDN2", "USE_LIBIDN2", "--with-libidn2", ""),
    ("idn", "winidn", ["lib/idn.c"], "Windows IdnToAscii", "USE_WIN32_IDN", "USE_WIN32_IDN", None, ""),
    ("idn", "appleidn", ["lib/idn.c"], "Apple ICU uidna + iconv", "USE_APPLE_IDN", "USE_APPLE_IDN", None, ""),
    ("psl", "libpsl", ["lib/psl.c"], "libpsl", "USE_LIBPSL", "CURL_USE_LIBPSL", "--with-libpsl", ""),
    # LDAP
    ("ldap", "ldap-generic-and-winldap", ["lib/ldap.c"], "OpenLDAP-less LDAP: Windows wldap32 or a vendor ldap library", "!CURL_DISABLE_LDAP && !USE_OPENLDAP", "CURL_DISABLE_LDAP", "--enable-ldap", ""),
    ("ldap", "openldap", ["lib/openldap.c"], "OpenLDAP", "!CURL_DISABLE_LDAP && USE_OPENLDAP", "CURL_DISABLE_LDAP", "--with-ldap", ""),
    ("ldap", "win32-ldap", ["lib/ldap.c"], "Windows wldap32", "USE_WIN32_LDAP", "USE_WIN32_LDAP", None, ""),
    # Local crypto
    ("crypto", "md4", ["lib/md4.c"], "local or OpenSSL/wolfSSL/CommonCrypto/Win32", "USE_CURL_NTLM_CORE", None, None, "DEPRECATE.md schedules local crypto removal"),
    ("crypto", "md5", ["lib/md5.c"], "local or OpenSSL/wolfSSL/mbedTLS/nettle", "...", None, None, "DEPRECATE.md schedules local crypto removal"),
    ("crypto", "hmac", ["lib/hmac.c"], "local", "...", None, None, "DEPRECATE.md schedules local crypto removal"),
    ("crypto", "sha256", ["lib/sha256.c"], "local or mbedTLS/OpenSSL/wolfSSL/nettle/PSA", "!CURL_DISABLE_AWS || !CURL_DISABLE_DIGEST_AUTH ...", None, None, "DEPRECATE.md schedules local crypto removal"),
    ("crypto", "sha512-256", ["lib/curl_sha512_256.c"], "OpenSSL/wolfSSL/nettle or local", "!CURL_DISABLE_DIGEST_AUTH && !CURL_DISABLE_SHA512_256", "CURL_DISABLE_SHA512_256", None, "DEPRECATE.md schedules local crypto removal"),
    ("crypto", "ed25519", ["lib/curl_ed25519.c"], "OpenSSL/wolfSSL/nettle", "!CURL_DISABLE_HTTP && !CURL_DISABLE_HTTPSIG", "CURL_DISABLE_HTTPSIG", None, "HTTP message signatures, EXPERIMENTAL"),
    # Platform glue
    ("platform", "amigaos", ["lib/amigaos.c"], "AmigaOS bsdsocket", "__AMIGA__", None, None, ""),
    ("platform", "macos-proxies", ["lib/macos.c"], "SystemConfiguration.framework", "CURL_MACOS_CALL_COPYPROXIES", None, None, ""),
    ("platform", "dllmain", ["lib/dllmain.c"], "OpenSSL (memleak prevention on Windows)", "USE_OPENSSL", None, None, ""),
]

OS_HEADER_PREFIXES = ("sys/", "netinet/", "arpa/", "net/", "bsdsocket/", "amitcp/", "proto/")
LIB_TOP_HEADERS = {"ares.h", "rustls.h", "quiche.h", "gsasl.h", "zlib.h", "zstd.h", "idn2.h", "ldap.h"}


def backend_records(cmake_opts, cfg_opts, protocols_data):
    """Build the curated backend list, anchored to mechanical evidence."""
    opt_by_name = {o["name"]: o for o in cmake_opts}
    cfg_sw = {s["name"] for o in cfg_opts for s in o["switches"]}
    recs = []
    covered = set()
    for cat, name, files, lib, macro, cmake, conf, notes in BACKENDS:
        rec = {"category": cat, "name": name, "library": lib, "build-macro": macro,
               "cmake-option": cmake, "configure-switch": conf, "notes": notes,
               "files": []}
        for f in files:
            p = ROOT / f
            check(p.exists(), f"backend file {f} exists")
            txt = strip_c_comments(src(f))
            snaps = pp_snapshots(txt)
            first = next((snaps[i][0] for i in range(len(snaps)) if snaps[i]), None)
            first_line = next((i + 1 for i in range(len(snaps)) if snaps[i]), None)
            incs = sorted(h for h in set(re.findall(r"^\s*#\s*include\s*<([^>]+)>", txt, re.MULTILINE))
                          if h not in STD_HEADERS and not h.startswith(OS_HEADER_PREFIXES)
                          and ("/" in h or h in LIB_TOP_HEADERS))
            rec["files"].append({"path": f, "first-guard": first, "first-guard-line": first_line,
                                 "external-includes": incs})
            covered.add(f)
        # Anchor: macro tokens named in the record appear in the files.
        tokens = re.findall(r"\b(?:USE|HAVE)_[A-Z0-9_]+", macro)
        if tokens and cat != "platform":
            joined = "\n".join(src(f) for f in files)
            for t in tokens[:1]:
                check(t in joined or t in read("lib/curl_setup.h"),
                      f"backend {name}: macro {t} appears in its files or curl_setup.h")
        if cmake:
            check(cmake in opt_by_name,
                  f"backend {name}: CMake option {cmake} exists")
        if cmake in opt_by_name:
            rec["cmake-enclosing-conditions"] = opt_by_name[cmake]["enclosing-conditions"]
            rec["cmake-option-line"] = f"{opt_by_name[cmake]['file']}:{opt_by_name[cmake]['line']}"
        if conf:
            check(re.match(r"--[\w-]+", conf).group(0) in cfg_sw, f"backend {name}: configure switch {conf} exists")
        recs.append(rec)

    # Every .c under the backend dirs must be covered.
    uncovered = []
    for d in ("lib/vtls", "lib/vquic", "lib/vssh", "lib/vauth", "lib/vdns"):
        for p in sorted((ROOT / d).glob("*.c")):
            rel = str(p.relative_to(ROOT))
            if rel not in covered:
                uncovered.append(rel)
    check(not uncovered, f"every .c in vtls/vquic/vssh/vauth/vdns is in the backend table: {uncovered}")
    return sorted(recs, key=lambda r: (r["category"], r["name"]))


DERIVED = ["USE_SSL", "USE_SSH", "USE_NTLM", "USE_CURL_NTLM_CORE", "USE_SPNEGO", "USE_KERBEROS5",
           "USE_HTTP2", "USE_HTTP3", "USE_THREADS", "USE_MUTEX", "USE_LIBIDN2", "CURLRES_IPV6",
           "CURLRES_IPV4", "CURLRES_ASYNCH", "CURLRES_SYNCH"]


def derived_macros():
    """Record where lib/curl_setup.h derives the umbrella USE_* macros."""
    txt = strip_c_comments(src("lib/curl_setup.h"))
    snaps = pp_snapshots(txt)
    out = []
    for name in DERIVED:
        found = []
        for m in re.finditer(rf"^\s*#\s*define\s+{name}\b", txt, re.MULTILINE):
            ln = line_of(txt, m.start())
            found.append({"line": ln, "conditions": list(snaps[ln - 1])})
        check(found, f"curl_setup.h defines {name}")
        out.append({"macro": name, "definitions": found})
    return out


# --------------------------------------------------------------------------
# 5. Environment variables
# --------------------------------------------------------------------------

ENV_CALL = re.compile(
    r"\b(curl_getenv|getenv|curlx_getenv|Curl_getenv|GetEnvironmentVariable[AW]?|secure_getenv|"
    r"vms_getenv|decc\$getenv)\s*\(\s*(\"([^\"]*)\")?")

ENV_EXCLUDED = {
    "lib/getenv.c": "implementation of curl_getenv itself",
    "lib/setup-vms.h": "OpenVMS getenv shim definitions",
    "include/curl/curl.h": "public declaration of curl_getenv",
}


def env_vars():
    """Collect the environment variables libcurl reads and cross-check the docs."""
    hits = []
    nonliteral = []
    files_with_ident = set()
    for rel, txt in strip_code_files():
        if not rel.startswith(("lib/", "include/")):
            continue
        if re.search(r"\b(?:curl_)?getenv\b|GetEnvironmentVariable", txt):
            files_with_ident.add(rel)
        snaps = None
        for m in ENV_CALL.finditer(txt):
            ln = line_of(txt, m.start())
            if m.group(3) is None:
                nonliteral.append({"file": rel, "line": ln, "function": m.group(1)})
                continue
            if snaps is None:
                snaps = pp_snapshots(txt)
            hits.append({"var": m.group(3), "file": rel, "line": ln, "function": m.group(1),
                         "conditions": list(snaps[ln - 1]),
                         "in-DEBUGBUILD-conditional": any("DEBUGBUILD" in c for c in snaps[ln - 1])})
    SOURCES.add("lib")
    # Non-literal sites must be explained.
    patterns = []
    unexplained = []
    for s in nonliteral:
        if s["file"] in ENV_EXCLUDED:
            s["explained-by"] = ENV_EXCLUDED[s["file"]]
        elif s["file"] == "lib/proxy.c":
            s["explained-by"] = "proxy variable name built at run time (see patterns)"
        else:
            unexplained.append(s)
    check(not unexplained, f"every non-literal getenv site is explained: {unexplained}")
    uncovered = files_with_ident - {h["file"] for h in hits} - {s["file"] for s in nonliteral}
    check(not uncovered, f"every file naming getenv produced a hit: {uncovered}")
    check(any(h["var"] == "SSLKEYLOGFILE" for h in hits) and any(h["var"] == "NETRC" for h in hits),
          "well-known env reads present (SSLKEYLOGFILE, NETRC)")

    proxy_c = strip_c_comments(read("lib/proxy.c"))
    names = {m.group(1) for m in re.finditer(r'(?:env_name|p)\s*=\s*"([A-Za-z_]+)"', proxy_c)}
    for want in ("https_proxy", "HTTPS_PROXY", "http_proxy", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"):
        check(want in names, f"proxy.c reads {want}")
    check("HTTP_PROXY" not in names, "proxy.c never reads uppercase HTTP_PROXY")
    patterns.append({
        "file": "lib/proxy.c",
        "pattern": "<scheme>_proxy then upper-cased <SCHEME>_PROXY, for every scheme except http/https",
        "http": "http_proxy (lowercase only; HTTP_PROXY is never read); ws falls back to http_proxy",
        "https": "https_proxy then HTTPS_PROXY; wss falls back to https_proxy/HTTPS_PROXY",
        "all": "all_proxy then ALL_PROXY",
        "no-proxy": "no_proxy then NO_PROXY",
        "literal-names-in-source": sorted(names),
    })

    # Per-variable records.
    byvar = {}
    for h in hits:
        r = byvar.setdefault(h["var"], {"var": h["var"], "read-sites": [], "scope": "lib"})
        r["read-sites"].append(f"{h['file']}:{h['line']}")
        r.setdefault("sites-in-DEBUGBUILD-conditional", 0)
        r["sites-in-DEBUGBUILD-conditional"] += 1 if h["in-DEBUGBUILD-conditional"] else 0
    for r in byvar.values():
        r["read-sites"].sort()
        r["all-sites-in-DEBUGBUILD-conditional"] = r["sites-in-DEBUGBUILD-conditional"] == len(r["read-sites"])

    # Docs.
    env_doc = src("docs/libcurl/libcurl-env.md")
    dbg_doc = src("docs/libcurl/libcurl-env-dbg.md")
    docs_env = re.findall(r"^## `([^`]+)`", env_doc, re.MULTILINE)
    docs_dbg = re.findall(r"^## `([^`]+)`", dbg_doc, re.MULTILINE)
    check(len(docs_env) == 8 and "SSLKEYLOGFILE" in docs_env, f"libcurl-env.md has 8 entries, got {len(docs_env)}")
    check(len(docs_dbg) == len(re.findall(r"^## ", dbg_doc, re.MULTILINE)), "env-dbg headings all parsed")

    # Literal proxy names inside lib/proxy.c, documented as ALL_PROXY, NO_PROXY, [scheme]_proxy.
    proxy_doc = {"all_proxy": "ALL_PROXY", "ALL_PROXY": "ALL_PROXY", "no_proxy": "NO_PROXY",
                 "NO_PROXY": "NO_PROXY", "http_proxy": "[scheme]_proxy",
                 "https_proxy": "[scheme]_proxy", "HTTPS_PROXY": "[scheme]_proxy"}
    for i, ln in enumerate(proxy_c.split("\n"), 1):
        for m in re.finditer(r'(?:env_name|p)\s*=\s*"([A-Za-z_]+)"', ln):
            r = byvar.setdefault(m.group(1), {"var": m.group(1), "read-sites": [], "scope": "lib",
                                              "sites-in-DEBUGBUILD-conditional": 0,
                                              "all-sites-in-DEBUGBUILD-conditional": False})
            r["read-sites"].append(f"lib/proxy.c:{i}")
            r["documented-as"] = proxy_doc[m.group(1)]

    # Tool-side reads for documented names not read by lib.
    tool_reads = {}
    for p in sorted((ROOT / "src").glob("*.c")):
        txt = strip_c_comments(p.read_text(errors="replace"))
        for m in ENV_CALL.finditer(txt):
            if m.group(3):
                tool_reads.setdefault(m.group(3), []).append(
                    f"{p.relative_to(ROOT)}:{line_of(txt, m.start())}")
    SOURCES.add("src")

    for d in docs_env:
        byvar.setdefault(d, {"var": d, "read-sites": [], "scope": "lib",
                             "sites-in-DEBUGBUILD-conditional": 0,
                             "all-sites-in-DEBUGBUILD-conditional": False})
    for d in docs_dbg:
        byvar.setdefault(d, {"var": d, "read-sites": [], "scope": "lib",
                             "sites-in-DEBUGBUILD-conditional": 0,
                             "all-sites-in-DEBUGBUILD-conditional": False})
    for v, r in byvar.items():
        r["documented-in"] = ("env" if v in docs_env or r.get("documented-as") in docs_env
                              else "env-dbg" if v in docs_dbg else "none")
        if v in tool_reads:
            r["tool-read-sites"] = sorted(tool_reads[v])
    byvar["[scheme]_proxy"]["read-sites"] = ["lib/proxy.c (name built from the scheme at run time)"]
    findings = {
        "read-by-lib-not-documented": sorted(
            v for v, r in byvar.items() if r["documented-in"] == "none"),
        "documented-env-dbg-but-never-read-by-lib": sorted(
            v for v, r in byvar.items()
            if r["documented-in"] == "env-dbg" and not r["read-sites"]),
        "documented-env-dbg-but-read-only-in-tool": sorted(
            v for v, r in byvar.items()
            if r["documented-in"] == "env-dbg" and not r["read-sites"] and "tool-read-sites" in r),
        "documented-env-dbg-but-a-read-site-has-no-DEBUGBUILD-conditional": sorted(
            v for v, r in byvar.items()
            if r["documented-in"] == "env-dbg" and r["read-sites"] and not r["all-sites-in-DEBUGBUILD-conditional"]),
        "documented-env-but-every-read-site-is-in-a-DEBUGBUILD-conditional": sorted(
            v for v, r in byvar.items()
            if r["documented-in"] == "env" and r["read-sites"]
            and r["all-sites-in-DEBUGBUILD-conditional"] and r["read-sites"][0][0].isalpha()),
        "documented-nowhere-read-anywhere": sorted(
            v for v, r in byvar.items()
            if r["documented-in"] != "none" and not r["read-sites"] and "tool-read-sites" not in r),
    }
    return {"variables": [byvar[k] for k in sorted(byvar)],
            "dynamic-name-patterns": patterns, "non-literal-sites": nonliteral,
            "excluded-files": ENV_EXCLUDED, "findings": findings,
            "doc-entries": {"libcurl-env.md": docs_env, "libcurl-env-dbg.md": docs_dbg},
            "literal-hit-count": len(hits)}


# --------------------------------------------------------------------------
# docs/FEATURES.md
# --------------------------------------------------------------------------

def features_prose():
    """Capture docs/FEATURES.md bullets as records."""
    rel = "docs/FEATURES.md"
    text = src(rel)
    recs = []
    section = None
    for i, line in enumerate(text.split("\n"), 1):
        m = re.match(r"^## (.*)$", line)
        if m:
            section = m.group(1)
            continue
        m = re.match(r"^- (.*)$", line)
        if m:
            recs.append({"path": rel, "line": i, "section": section, "text": m.group(1),
                         "status": "hypothesis"})
    n_bullets = len(re.findall(r"^- ", text, re.MULTILINE))
    check(len(recs) == n_bullets and n_bullets > 100, f"FEATURES.md bullets {len(recs)}/{n_bullets}")
    check(not any(r["section"] is None for r in recs), "every bullet has a section")
    return recs


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def main():
    """Generate inventory/features.{json,md}."""
    protocols, cm_features, cm_ssl = parse_protocols()
    features = parse_features(cm_features, protocols)
    cmake_opts, cmake_skipped = parse_cmake_options()
    cfg_opts, cfg_skipped = parse_configure_options()
    ac_texts = [read(f) for f in ["configure.ac", "acinclude.m4"]] + [
        read(str(p.relative_to(ROOT))) for p in sorted((ROOT / "m4").glob("*.m4"))]
    disable = parse_disable_macros(cmake_opts, ac_texts)
    tls = tls_backends(cm_ssl)
    backends = backend_records(cmake_opts, cfg_opts, protocols)
    derived = derived_macros()
    env = env_vars()
    prose = features_prose()

    data = {
        "protocols": protocols,
        "features": features,
        "build-options": {
            "cmake": cmake_opts, "cmake-skipped": cmake_skipped,
            "configure": cfg_opts, "configure-skipped": cfg_skipped,
            "curl-disable": disable,
        },
        "backends": {"tls": tls, "all": backends, "derived-macros": derived},
        "environment": env,
        "prose-features": prose,
    }

    md = []
    emit = md.append
    emit("# Features and backends\n")
    emit("Derived from `lib/protocol.c`, `lib/version.c`, `src/tool_help.c`, `src/curlinfo.c`, "
              "`CMakeLists.txt`, `configure.ac`, `docs/CURL-DISABLE.md`, `lib/vtls/vtls.c`, the "
              "backend directories, `lib/**` getenv calls and `docs/FEATURES.md`. "
              "The JSON is the complete record.\n")
    sch = protocols["schemes"]
    emit(f"## Protocols ({len(sch)} schemes)\n")
    emit(md_table(
        ["scheme", "port", "bit", "bit#", "handler files", "absent when", "flags"],
        [[s["name"], s["default-port"], s["protocol-bit"], s["protocol-bit-number"],
          s["handler-files"] or "-", s["handler-absent-when"] or "-",
          ", ".join(f.removeprefix("PROTOPT_") for f in s["flags"])] for s in sch]))
    emit(f"Public CURLPROTO bits with no scheme (removed protocols): "
              f"{', '.join(protocols['curlproto-unmapped-public-bits'])}.\n")
    emit("Tool-only pseudo protocols: ipfs, ipns.\n")
    emit(md_table(["protocol discrepancy", "lib/protocol.c", "lib/version.c"],
                  [[d["what"], d["protocol.c"], d["version.c"]] for d in protocols["discrepancies"]]))
    emit("## Features (curl_version_info, exact printed spelling)\n")
    emit(md_table(
        ["name", "bit", "runtime check", "conditions", "source"],
        [[f["name"], f["bit"] or "-", f["runtime-check"] or "-", " && ".join(f["conditions"]),
          f["source"]] for f in sorted(features["features"] + features["tool-added-features"],
                                       key=lambda f: f["name"].lower())]))
    emit(md_table(["cross-check", "names"], [
        ["CURL_VERSION_ bits with no table row", features["bits-not-in-table"]],
        ["documented in curl_version_info.md, not in the table", features["docs-missing-from-table"]],
        ["in the table, not documented", features["table-missing-from-docs"]],
        ["in CMake's feature list, not printed", features["cmake-only-feature-names"]],
        ["printed, not in CMake's feature list", features["printed-only-feature-names"]],
        ["runtests.pl feature regexes matching no printed feature",
         features["runtests-regexes-matching-no-printed-feature"]]]))
    emit(f"Test-gating vocabulary: {len(features['test-feature-vocabulary'])} names across "
              f"{features['test-files-with-features']} test files, all with a known origin.\n")
    emit("## Build options\n")
    emit(f"- CMake: {len(cmake_opts)} options/cache variables\n"
              f"- configure: {len(cfg_opts)} AC_ARG_ENABLE/AC_ARG_WITH invocations\n"
              f"- CURL_DISABLE_*: {len(disable['documented'])} documented, "
              f"{len(disable['macros'])} distinct names across all sources\n")
    mm = disable["mismatches"]
    emit(md_table(["mismatch", "count", "names"],
                       [[k, len(v), v] for k, v in mm.items()]))
    emit("## TLS backends (from `available_backends` and `Curl_ssl_*` definitions)\n")
    emit(md_table(
        ["index", "symbol", "name", "id", "file", "capabilities"],
        [[a["index"], a["symbol"], d["name"], d["id"], d["file"],
          len(d["capabilities"])]
         for a in tls["available-backends"] for d in tls["backend-definitions"]
         if d["symbol"] == a["symbol"]]))
    emit("Default selection chain (vtls.c): " + ", ".join(
        f"{c['symbol']} [{c['condition']}]" for c in tls["default-selection-chain"]) + "\n")
    emit("## Backends by category\n")
    emit(md_table(["category", "name", "library", "build macro", "CMake", "configure", "files"],
                       [[b["category"], b["name"], b["library"], b["build-macro"],
                         b["cmake-option"] or "-", b["configure-switch"] or "-",
                         [f["path"] for f in b["files"]]] for b in backends]))
    emit("## Environment variables read by libcurl\n")
    emit(md_table(["variable", "documented in", "read sites"],
                       [[v["var"], v["documented-in"], len(v["read-sites"])]
                        for v in env["variables"]]))
    emit(md_table(["finding", "variables"], [[k, v] for k, v in env["findings"].items()]))
    emit(f"## docs/FEATURES.md\n\n{len(prose)} bullet records.\n")

    common.write("features", data, "\n".join(md), SOURCES)


if __name__ == "__main__":
    main()
