#!/usr/bin/env python3
"""
Inventory of the C test suite the rewrite is scored on.

Sources of truth (all under tests/):
  data/testNNNN            test case files (getpart.pm format, see docs/tests/FILEFORMAT.md)
  data/Makefile.am         distribution list (runtests only warns when a test is missing here)
  data/DISABLED            globally disabled tests, with %if conditionals
  libtest/Makefile.inc     libtest programs; unit/, tunit/ Makefile.inc for the unit tests
  http/test_*.py           pytest suite
  servers.pm, server/      test server keyword -> program mapping

runtests.pl decides what runs by listing tests/data/ for ^test[0-9]+$ files
(not by Makefile.am) and subtracting DISABLED.
"""

import ast
import collections
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common
from common import ROOT, check, md_table

TESTS = ROOT / "tests"
DATA = TESTS / "data"
sources = set()


def rel(p):
    return str(pathlib.Path(p).relative_to(ROOT))


def src(p):
    sources.add(rel(p))


# --------------------------------------------------------------------------
# getpart.pm port (line based, bytes kept via latin-1)
# --------------------------------------------------------------------------

def load_lines(path):
    raw = pathlib.Path(path).read_bytes()
    text = raw.decode("latin-1")
    # runtests loads the original with binmode ':crlf': CRLF -> LF
    text = text.replace("\r\n", "\n")
    # `%repeat[..]%</tag>`: preprocessing makes the closing tag start a line
    text = re.sub(r"(%repeat\[[^\]\n]*\]%)(</\w+>)", r"\1\n\2", text)
    return raw, text.splitlines(keepends=True)


def getpart(xml, section, part):
    this, inside = [], 0
    for line in xml:
        if not inside and re.match(rf"^ *<{section}", line):
            inside += 1
        elif inside >= 1 and re.match(rf"^ *<{part}[ >]", line):
            if inside > 1:
                this.append(line)
            inside += 1
        elif inside >= 2 and re.match(rf"^ *</{part}[ >]", line):
            if inside > 2:
                this.append(line)
            inside -= 1
        elif inside >= 1 and re.match(rf"^ *</{section}", line):
            if inside > 1:
                return None  # 'missing </part> tag before </section>'
            return this
        elif inside >= 2:
            this.append(line)
    return this


ATTR_RE = re.compile(r""" *([^=]*)= *("([^"]*)"|'([^']*)')""")


def parse_attrs(attr):
    out = {}
    while True:
        m = ATTR_RE.match(attr)
        if not m:
            break
        out[m.group(1)] = m.group(3) if m.group(3) is not None else m.group(4)
        attr = attr[m.end():]
    return out


def getpartattr(xml, section, part):
    inside = 0
    for line in xml:
        if not inside and re.match(rf"^ *<{section}", line):
            inside += 1
        if inside == 1 and (m := re.match(rf"^ *<{part} ([^>]*)", line)):
            return parse_attrs(m.group(1))
        if inside == 1 and re.match(rf"^ *</{section}>", line):
            break
    return {}


def partexists(xml, section, part):
    inside = 0
    for line in xml:
        if not inside and re.match(rf"^ *<{section}", line):
            inside += 1
        elif inside == 1 and re.match(rf"^ *<{part}[ >]", line):
            return True
        elif inside == 1 and re.match(rf"^ *</{section}", line):
            return False
    return False


def enumerate_parts(xml):
    """
    List (section, part, attrs) for the four top-level sections.

    Returns (parts, problems), problems being unterminated tags.
    """
    parts, problems = [], []
    section = None
    closing = None
    for line in xml:
        if closing:
            if re.match(rf"^ *</{closing[1]}[ >]", line):
                closing = None
            continue
        if section is None:
            m = re.match(r"^ *<(info|reply|client|verify)>", line)
            if m:
                section = m.group(1)
            continue
        if re.match(rf"^ *</{section}>", line):
            section = None
            continue
        m = re.match(r"^ *<([A-Za-z][A-Za-z0-9_-]*)([ >].*)?$", line.rstrip("\n"))
        if m:
            name = m.group(1)
            attr = ""
            am = re.match(r"^ *<[^ >]+ ([^>]*)", line)
            if am:
                attr = am.group(1)
            parts.append((section, name, parse_attrs(attr)))
            closing = (section, name)
    if closing:
        problems.append(f"unterminated <{closing[1]}> in <{closing[0]}>")
    if section:
        problems.append(f"unterminated <{section}>")
    return parts, problems


def lines_text(lines):
    return [l.strip() for l in lines if l.strip()]


# --------------------------------------------------------------------------
# 1. test data
# --------------------------------------------------------------------------

MACRO_RES = {
    "hex": r"%hex\[", "b64": r"%b64\[", "repeat": r"%repeat\[",
    "include": r"%include(text)? ", "if": r"^ *%if ", "days": r"%days\[",
    "alternatives": r"%alternatives\[", "CR": r"%CR\b", "SP": r"%SP\b",
    "TAB": r"%TAB\b", "AMP": r"%AMP\b", "GT": r"%GT\b", "LT": r"%LT\b",
    "EMPTY": r"%EMPTY\b",
}
VAR_RE = re.compile(r"%([A-Z][A-Z0-9_]*[A-Z0-9])")

LIBTEST_DEFAULT = "libtest"


def parse_test(path):
    num = int(path.name[4:])
    raw, xml = load_lines(path)
    text = "".join(xml)
    src(path)
    t = {"number": num}
    problems = []

    if not raw.startswith(b'<?xml version="1.0" encoding="US-ASCII"?>'):
        problems.append("missing XML prolog")
    if not re.search(r"^<testcase", text, re.MULTILINE):
        problems.append("no <testcase>")
    cr, lf = raw.count(b"\r"), raw.count(b"\n")
    t["eol"] = ("crlf" if cr == lf and cr else "lf" if cr == 0 and lf else
                "mixed" if cr and lf else "other")
    t["non_ascii"] = any(b > 127 for b in raw)
    t["nul"] = b"\0" in raw
    t["bytes"] = len(raw)

    def gp(sec, part):
        r = getpart(xml, sec, part)
        if r is None:
            problems.append(f"missing </{part}> before </{sec}>")
            return []
        return r

    kw = [l.rstrip("\n") for l in gp("info", "keywords")]
    t["keywords"] = sorted({k for k in (x.strip() for x in kw) if k})
    feats = [l.strip() for l in gp("client", "features") if l.strip()]
    t["features"] = sorted(set(feats))
    srv = []
    for l in gp("client", "server"):
        l = l.strip()
        if l:
            srv.append(l)
    t["servers"] = srv  # raw lines, in file order
    t["killserver"] = [l.strip() for l in gp("client", "killserver") if l.strip()]
    tool = [l.strip() for l in gp("client", "tool")]
    t["tool"] = tool[0] if tool and tool[0] else None
    t["name"] = " ".join(lines_text(gp("client", "name")))
    cmd_exists = partexists(xml, "client", "command")
    t["has_command"] = cmd_exists
    cmdattr = getpartattr(xml, "client", "command")
    t["command_type"] = cmdattr.get("type")
    t["command_option"] = cmdattr.get("option")
    cmd = gp("client", "command")
    t["command"] = " ".join(l.strip("\n") for l in cmd).strip()
    t["setenv"] = sorted({l.split("=", 1)[0].strip()
                          for l in gp("client", "setenv") if l.strip()})
    pre = gp("client", "precheck")
    t["precheck"] = " ".join(lines_text(pre)) if pre else None
    t["has_precheck"] = partexists(xml, "client", "precheck")
    ec = gp("verify", "errorcode")
    t["errorcode"] = " ".join(lines_text(ec)) if partexists(xml, "verify", "errorcode") else None
    t["postcheck"] = partexists(xml, "verify", "postcheck")
    t["disable"] = [l.strip() for l in gp("client", "disable") if l.strip()]

    parts, pr = enumerate_parts(xml)
    problems += pr
    t["parts"] = sorted({f"{s}/{p}" for s, p, _ in parts})
    attrs = collections.defaultdict(set)
    for s, p, a in parts:
        for k in a:
            attrs[k].add(f"{s}/{re.sub(r'[0-9]+$', 'N', p)}")
    t["attrs"] = {k: sorted(v) for k, v in sorted(attrs.items())}
    t["attr_values"] = sorted({f"{k}={v}" for _, _, a in parts for k, v in a.items()
                               if k in ("crlf", "mode", "nonewline", "nocheck",
                                        "sendzero", "type", "option", "base64", "hex",
                                        "delay", "timeout")})
    # testcase element attributes (none expected)
    m = re.search(r"^ *<testcase ([^>]*)", text, re.MULTILINE)
    t["testcase_attrs"] = parse_attrs(m.group(1)) if m else {}

    t["macros"] = sorted(k for k, r in MACRO_RES.items()
                         if re.search(r, text, re.MULTILINE))
    t["variables"] = sorted(set(VAR_RE.findall(text)) -
                            {"CR", "SP", "TAB", "AMP", "GT", "LT", "EMPTY"})
    t["problems"] = problems
    return t


def classify(t):
    """Port of runner.pm singletest_run's tool selection."""
    kws = set(t["keywords"])
    if t["command_type"] == "perl":
        return "perl-script", None
    if t["command_type"] == "shell":
        return "shell-script", None
    if not t["tool"] and not (kws & {"unittest", "tunittest", "libtest"}):
        return "curl", None
    tool = t["tool"]
    if not tool:
        if "unittest" in kws:
            tool = f"unit{t['number']}"
        elif "libtest" in kws:
            tool = f"lib{t['number']}"
        elif "tunittest" in kws:
            tool = f"tool{t['number']}"
    if re.match(r"(lib|cli_)", tool):
        return "libtest", tool
    if tool.startswith("tool"):
        return "tunit", tool
    if tool.startswith("unit"):
        return "unit", tool
    return "unresolvable", tool


# --------------------------------------------------------------------------
# 2. Makefile.am / DISABLED
# --------------------------------------------------------------------------

def parse_makefile_am():
    p = DATA / "Makefile.am"
    src(p)
    lines = p.read_text().splitlines()
    mode = None
    testcases, extra = [], []
    for l in lines:
        if l.startswith("TESTCASES"):
            mode = "tc"
            continue
        if l.startswith("EXTRA_DIST"):
            mode = "extra"
            continue
        if mode and not l.strip():
            mode = None
            continue
        if not mode:
            continue
        tok = l.strip().rstrip("\\").strip()
        if not tok:
            continue
        (testcases if mode == "tc" else extra).append(tok)
    return testcases, extra


def parse_disabled():
    p = DATA / "DISABLED"
    src(p)
    entries, directives = [], []
    stack = []
    noncomment = 0
    for n, l in enumerate(p.read_text().splitlines(), 1):
        if re.match(r"^ *#", l):
            continue
        if not l.strip():
            continue
        noncomment += 1
        m = re.match(r"^ *%if ([A-Za-z0-9!_-]*)", l)
        if m:
            stack.append(m.group(1))
            directives.append({"line": n, "text": l.strip()})
            continue
        if re.match(r"^ *%endif", l):
            stack.pop()
            directives.append({"line": n, "text": l.strip()})
            continue
        if re.match(r"^ *%else", l):
            directives.append({"line": n, "text": l.strip()})
            stack[-1] = "!" + stack[-1] if not stack[-1].startswith("!") else stack[-1][1:]
            continue
        m = re.match(r"^\s*(\d+)\s*$", l)
        check(m, f"DISABLED: unparsed line {n}: {l!r}")
        entries.append({"test": int(m.group(1)), "line": n, "conditions": list(stack)})
    check(not stack, "DISABLED: unbalanced %if")
    # comments immediately above an entry (explanatory text from the file)
    return entries, directives, noncomment


def disabled_comments():
    """Comment blocks (contiguous '#' lines) directly above each entry/directive."""
    p = DATA / "DISABLED"
    out = {}
    block = []
    for l in p.read_text().splitlines():
        if re.match(r"^ *#", l):
            block.append(l.lstrip(" #").rstrip())
            continue
        m = re.match(r"^\s*(\d+)\s*$", l)
        if m and block:
            out[int(m.group(1))] = " ".join(b for b in block if b)
        if l.strip() and not l.startswith("%") or not l.strip():
            block = []
    return out


# --------------------------------------------------------------------------
# 3. libtest / unit / tunit
# --------------------------------------------------------------------------

def read_makefile_inc_list(path, var="TESTS_C"):
    src(path)
    text = path.read_text()
    m = re.search(rf"^{var}\s*=\s*((?:.*\\\n)*.*)$", text, re.MULTILINE)
    check(m, f"{path}: no {var}")
    return sorted(t for t in re.split(r"[\s\\]+", m.group(1)) if t)


FUNC_KW = {"if", "while", "for", "switch", "return", "sizeof", "defined", "do",
           "else", "case", "typeof", "__attribute__", "__declspec", "static_assert"}


def build_func_index():
    """
    name -> {"files": [...], "unittest": bool}: non-static function
    definitions in lib/ and src/ (column-0 heuristics), plus UNITTEST
    (exposed for unit tests) ones."""
    idx = collections.defaultdict(lambda: {"files": set(), "unittest": False})
    for base in ("lib", "src"):
        for p in sorted((ROOT / base).rglob("*.c")):
            try:
                lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, l in enumerate(lines):
                if not l or l[0] in " \t#}/{*" or l.rstrip().endswith(";"):
                    continue
                if re.match(r"(typedef|extern|struct\s+\w+\s*\{|enum|union)\b", l):
                    continue
                m = re.match(r"^((?:[A-Za-z_][\w]*[\s\*]+)*)\*?([A-Za-z_]\w*)\s*\(", l)
                if not m:
                    continue
                prefix, name = m.group(1), m.group(2)
                if name in FUNC_KW:
                    continue
                if not prefix.strip():
                    # return type on the previous line(s)
                    j = i - 1
                    while j >= 0 and lines[j].strip() == "":
                        j -= 1
                    prev = lines[j] if j >= 0 else ""
                    if ((not prev or prev[0] in " \t#}/{*" or prev.rstrip().endswith((";", "{", "}", ")")))
                            and not re.match(r"^(UNITTEST|static|CURL_EXTERN)", prev)
                            and not re.match(r"^[\w\s\*]+$", prev)):
                        # a lone `name(` after a statement end: not a definition head
                        continue
                    prefix = prev
                if re.search(r"\bstatic\b", prefix) and "UNITTEST" not in prefix:
                    continue
                # a definition's parameter list must not end the statement on the same line
                entry = idx[name]
                entry["files"].add(rel(p))
                if "UNITTEST" in prefix:
                    entry["unittest"] = True
    return idx


def c_calls(text):
    """Return (called identifiers, text with comments and literals blanked)."""
    def blank(m):
        t = m.group(0)
        if t.startswith("/"):
            return " "
        return t[0] * 2

    text = re.sub(r"/\*.*?\*/|//[^\n]*|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'",
                  blank, text, flags=re.DOTALL)
    return set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", text)), text


CURL_SYM_RE = re.compile(r"\b(CURL[A-Z]*_[A-Z0-9_]+)\b")
API_RE = re.compile(r"\b(curl_[a-z0-9_]+)\s*\(")


def analyze_c_test(path, kind, funcidx):
    src(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    incs = re.findall(r'^\s*#\s*include\s+[<"]([^>"]+)[>"]', text, re.MULTILINE)
    calls, stripped = c_calls(text)
    entry = re.findall(r"^(?:static\s+)?(?:CURLcode|int)\s+(test_\w+)\s*\(", text, re.MULTILINE)
    rec = {
        "file": rel(path),
        "entry": entry,
        "includes": sorted(set(incs)),
        "bytes": len(text.encode()),
    }
    rec["curl_api_calls"] = sorted(set(API_RE.findall(stripped)))
    rec["curl_symbols"] = sorted(set(CURL_SYM_RE.findall(stripped)))
    if kind in ("unit", "tunit"):
        internal = {}
        for name in sorted(calls):
            if name in funcidx and name not in entry:
                f = funcidx[name]
                if name.startswith("curl_"):
                    continue  # public API, recorded in curl_api_calls
                internal[name] = {"files": sorted(f["files"]), "unittest_exposed": f["unittest"]}
        rec["internal_functions"] = internal
        files = collections.Counter()
        for v in internal.values():
            for fl in v["files"]:
                files[fl] += 1
        rec["exercises_files"] = sorted(files)
        hdrs = []
        for h in rec["includes"]:
            if h in ("unitcheck.h", "first.h", "curl_setup.h") or h.startswith(("curl/", "curlx/")) and False:
                continue
            for base in ("lib", "src", "lib/curlx", "src/toolx"):
                if (ROOT / base / h).exists():
                    hdrs.append(f"{base}/{h}")
                    break
        rec["internal_headers"] = sorted(set(hdrs))
        rec["platform_conditional"] = bool(re.search(r"#\s*if.*(_WIN32|MSDOS)", text))
    return rec


# --------------------------------------------------------------------------
# 4. pytest
# --------------------------------------------------------------------------

def dec_info(d):
    s = ast.unparse(d)
    out = {"text": s}
    if isinstance(d, ast.Call):
        fn = ast.unparse(d.func)
        out["call"] = fn
        if fn.endswith("mark.skipif"):
            cond = next((ast.unparse(k.value) for k in d.keywords if k.arg == "condition"),
                        ast.unparse(d.args[0]) if d.args else None)
            reason = next((ast.unparse(k.value) for k in d.keywords if k.arg == "reason"), None)
            out.update(kind="skipif", condition=cond, reason=reason)
        elif fn.endswith("mark.parametrize"):
            names = ast.unparse(d.args[0]) if d.args else None
            n = None
            if len(d.args) > 1 and isinstance(d.args[1], (ast.List, ast.Tuple)):
                n = len(d.args[1].elts)
            out.update(kind="parametrize", argnames=names, n_values=n)
        elif ".mark." in fn or fn.startswith("pytest.mark"):
            out.update(kind="mark")
        else:
            out.update(kind="other")
    else:
        out["kind"] = "other"
    return out


def parse_pytests():
    out = []
    for p in sorted((TESTS / "http").glob("test_*.py")):
        src(p)
        tree = ast.parse(p.read_text())
        mod = {"file": rel(p), "classes": [], "functions": [], "module_marks": []}
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets):
                mod["module_marks"].append(ast.unparse(node.value))
            if isinstance(node, ast.ClassDef):
                cdecs = [dec_info(d) for d in node.decorator_list]
                cls = {"name": node.name, "decorators": cdecs, "tests": []}
                for fn in node.body:
                    if isinstance(fn, ast.FunctionDef) and fn.name.startswith("test_"):
                        cls["tests"].append(func_rec(fn))
                mod["classes"].append(cls)
            elif isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                mod["functions"].append(func_rec(node))
        out.append(mod)
    return out


def func_rec(fn):
    decs = [dec_info(d) for d in fn.decorator_list]
    args = [a.arg for a in fn.args.args if a.arg != "self"]
    return {"name": fn.name, "line": fn.lineno, "fixtures": args, "decorators": decs}


def parse_conftest_fixtures():
    p = TESTS / "http" / "conftest.py"
    src(p)
    tree = ast.parse(p.read_text())
    fx = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            fx.extend({"name": node.name, "decorator": ast.unparse(d),
                       "args": [a.arg for a in node.args.args]}
                      for d in node.decorator_list if "fixture" in ast.unparse(d))
    return fx


# --------------------------------------------------------------------------
# 5. servers
# --------------------------------------------------------------------------

# Hand-read from servers.pm startservers()/run*server(); every row is verified
# below against the script/program text it names.
# keyword -> (driver, c_programs, external, notes)
SERVER_MAP = {
    "ftp": ("tests/ftpserver.pl", ["sockfilt"], [], "pingpong server; ftp"),
    "ftp-ipv6": ("tests/ftpserver.pl", ["sockfilt"], [], "ftp over IPv6"),
    "ftps": ("tests/secureserver.pl", ["sockfilt"], ["stunnel"], "ftp server + stunnel front"),
    "pop3": ("tests/ftpserver.pl", ["sockfilt"], [], "pingpong server"),
    "imap": ("tests/ftpserver.pl", ["sockfilt"], [], "pingpong server"),
    "smtp": ("tests/ftpserver.pl", ["sockfilt"], [], "pingpong server"),
    "pop3s": ("tests/secureserver.pl", ["sockfilt"], ["stunnel"], "pop3 + stunnel"),
    "imaps": ("tests/secureserver.pl", ["sockfilt"], ["stunnel"], "imap + stunnel"),
    "smtps": ("tests/secureserver.pl", ["sockfilt"], ["stunnel"], "smtp + stunnel"),
    "http": ("tests/http-server.pl", ["sws"], [], ""),
    "http-ipv6": ("tests/http-server.pl", ["sws"], [], ""),
    "http-proxy": ("tests/http-server.pl", ["sws"], [], "sws in proxy mode"),
    "http-unix": ("tests/http-server.pl", ["sws"], [], "Unix domain socket"),
    "https": ("tests/secureserver.pl", ["sws"], ["stunnel"], "http server + stunnel"),
    "https-mtls": ("tests/secureserver.pl", ["sws"], ["stunnel"], "http + stunnel with client cert verify"),
    "https-proxy": ("tests/secureserver.pl", ["sws"], ["stunnel"], "http-proxy + stunnel"),
    "http/2": ("tests/http2-server.pl", ["sws"], ["nghttpx"], "nghttpx fronting the http server"),
    "http/3": ("tests/http3-server.pl", ["sws"], ["nghttpx"], "nghttpx (QUIC) fronting the http server; not listed in FILEFORMAT.md"),
    "gopher": ("tests/http-server.pl", ["sws"], [], ""),
    "gopher-ipv6": ("tests/http-server.pl", ["sws"], [], ""),
    "gophers": ("tests/secureserver.pl", ["sws"], ["stunnel"], "gopher + stunnel"),
    "rtsp": ("tests/rtspserver.pl", ["rtspd"], [], ""),
    "rtsp-ipv6": ("tests/rtspserver.pl", ["rtspd"], [], ""),
    "tftp": ("tests/tftpserver.pl", ["tftpd"], [], ""),
    "tftp-ipv6": ("tests/tftpserver.pl", ["tftpd"], [], ""),
    "sftp": ("tests/sshserver.pl", [], ["sshd (OpenSSH)", "sftp-server"], ""),
    "scp": ("tests/sshserver.pl", [], ["sshd (OpenSSH)"], ""),
    "socks4": ("tests/servers.pm", ["socksd"], [], "runsocksserver"),
    "socks5": ("tests/servers.pm", ["socksd"], [], "runsocksserver"),
    "socks5unix": ("tests/servers.pm", ["socksd"], [], "socks5 over Unix socket"),
    "mqtt": ("tests/servers.pm", ["mqttd"], [], "runmqttserver"),
    "mqtts": ("tests/servers.pm", ["mqttd"], ["stunnel"], "mqtt + stunnel"),
    "dict": ("tests/dictserver.py", [], ["python3"], ""),
    "telnet": ("tests/negtelnetserver.py", [], ["python3"], ""),
    "dns": ("tests/servers.pm", ["dnsd"], [], "rundnsserver; implicit for all runs"),
    "file": (None, [], [], "no server (file:// protocol)"),
}


def main():
    # ---------------------------------------------------------------- tests
    files = sorted(p for p in DATA.iterdir() if re.fullmatch(r"test[0-9]+", p.name))
    n_files = len(files)
    # .gitignore is VCS metadata, not test data
    other_files = sorted(p.name for p in DATA.iterdir()
                         if not re.fullmatch(r"test[0-9]+", p.name) and p.name != ".gitignore")
    # independent count: shell-visible entries matching the runtests pattern
    check(n_files == sum(1 for p in DATA.iterdir()
                         if p.is_file() and re.match(r"^test([0-9]+)$", p.name)),
          "test file count disagrees with runtests regex count")

    tests = [parse_test(p) for p in files]
    check(len(tests) == n_files, "parsed test count != file count")
    check(len({t["number"] for t in tests}) == n_files, "duplicate test numbers")
    bynum = {t["number"]: t for t in tests}

    # positive controls on the parser
    t1 = bynum[1]
    check(t1["keywords"] == ["HTTP", "HTTP GET"], f"test1 keywords: {t1['keywords']}")
    check(t1["servers"] == ["http"], "test1 server")
    check(t1["name"] == "HTTP GET", "test1 name")
    check(t1["has_command"] and t1["command"] == "http://%HOSTIP:%HTTPPORT/%TESTNUMBER",
          "test1 command")
    check(bynum[1300]["keywords"] == ["llist", "unittest"] and bynum[1300]["features"] == ["unittest"],
          "test1300 keywords/features")
    check(bynum[305]["errorcode"] is not None and "," in bynum[305]["errorcode"],
          "test305 should list several accepted error codes")
    # FILEFORMAT.md says "See test 237" for the list form; it is a single code there
    doc_claims = [{"claim": "docs/tests/FILEFORMAT.md: errorcode list syntax 'See test 237 for an example'",
                   "status": "hypothesis-refuted" if "," not in (bynum[237]["errorcode"] or "") else "holds",
                   "actual_237": bynum[237]["errorcode"],
                   "tests_with_lists": sorted(t["number"] for t in tests if "," in (t["errorcode"] or ""))}]

    # runner classification
    for t in tests:
        t["runner"], t["tool_name"] = classify(t)
    # --- every test must have non-empty keywords (runtests skips otherwise)
    nokw = [t["number"] for t in tests if not t["keywords"]]

    # --------------------------------------------------- Makefile.am/DISABLED
    mk_tc, mk_extra = parse_makefile_am()
    mk_nums = []
    for tok in mk_tc:
        m = re.fullmatch(r"test(\d+)", tok)
        check(m, f"Makefile.am TESTCASES: unexpected token {tok!r}")
        mk_nums.append(int(m.group(1)))
    discrepancies = {"tests_not_in_makefile_am": sorted(set(bynum) - set(mk_nums)),
                     "makefile_am_without_file": sorted(set(mk_nums) - set(bynum)),
                     "makefile_am_duplicates": sorted(n for n, c in collections.Counter(mk_nums).items() if c > 1),
                     "makefile_am_not_sorted": mk_nums != sorted(mk_nums)}
    extra_files = [e for e in mk_extra if e != "$(TESTCASES)"]
    discrepancies["extra_dist_missing_file"] = sorted(e for e in extra_files if not (DATA / e).exists())
    discrepancies["data_files_not_in_extra_dist"] = sorted(set(other_files) - set(extra_files) - {"Makefile.am"})

    d_entries, d_directives, d_noncomment = parse_disabled()
    check(len(d_entries) + len(d_directives) == d_noncomment,
          "DISABLED: parsed entries+directives != non-comment non-blank lines")
    # independent count with grep-like logic
    indep = sum(1 for l in (DATA / "DISABLED").read_text().splitlines()
                if l.strip() and not re.match(r"^ *#", l))
    check(indep == d_noncomment, "DISABLED independent count mismatch")
    comments = disabled_comments()
    for e in d_entries:
        check(e["test"] in bynum, f"DISABLED lists test {e['test']} with no file "
              "(runtests.pl exits hard on this)")
        e["comment"] = comments.get(e["test"])
    disabled_uncond = sorted({e["test"] for e in d_entries if not e["conditions"]})
    disabled_any = sorted({e["test"] for e in d_entries})
    dup = sorted(n for n, c in collections.Counter(e["test"] for e in d_entries).items() if c > 1)
    check({594, 836, 882, 938, 1182, 1184} <= set(disabled_uncond), "DISABLED known entries missing")
    check(not (set(disabled_uncond) - set(bynum)), "unconditional DISABLED without file")

    # --------------------------------------------- libtest / unit / tunit
    lib_listed = read_makefile_inc_list(TESTS / "libtest" / "Makefile.inc")
    unit_listed = read_makefile_inc_list(TESTS / "unit" / "Makefile.inc")
    tunit_listed = read_makefile_inc_list(TESTS / "tunit" / "Makefile.inc")
    src(TESTS / "libtest" / "CMakeLists.txt")
    src(TESTS / "libtest" / "mk-lib1521.pl")
    lib_files = sorted(p.name for p in (TESTS / "libtest").glob("lib*.c")) + \
        sorted(p.name for p in (TESTS / "libtest").glob("cli_*.c"))
    unit_files = sorted(p.name for p in (TESTS / "unit").glob("unit*.c"))
    tunit_files = sorted(p.name for p in (TESTS / "tunit").glob("tool*.c"))
    discrepancies["libtest_listed_without_file"] = sorted(set(lib_listed) - set(lib_files))
    discrepancies["libtest_file_not_listed"] = sorted(set(lib_files) - set(lib_listed))
    discrepancies["unit_listed_without_file"] = sorted(set(unit_listed) - set(unit_files))
    discrepancies["unit_file_not_listed"] = sorted(set(unit_files) - set(unit_listed))
    discrepancies["tunit_listed_without_file"] = sorted(set(tunit_listed) - set(tunit_files))
    discrepancies["tunit_file_not_listed"] = sorted(set(tunit_files) - set(tunit_listed))
    check(len(lib_listed) == len(set(lib_listed)), "duplicate in libtest Makefile.inc")
    check("lib500.c" in lib_listed and "unit1300.c" in unit_listed and "tool1604.c" in tunit_listed,
          "known tool sources missing from Makefile.inc lists")

    funcidx = build_func_index()
    check("Curl_llist_init" in funcidx and any("llist.c" in f for f in funcidx["Curl_llist_init"]["files"]),
          "func index: Curl_llist_init not found in llist.c")
    check(funcidx["curl_easy_perform"]["files"], "func index: curl_easy_perform not found")
    check(sum(1 for v in funcidx.values() if v["unittest"]) >= 40,
          "func index: too few UNITTEST-exposed functions")

    programs = {}  # tool name -> record
    for f in lib_files:
        programs[f[:-2]] = dict(analyze_c_test(TESTS / "libtest" / f, "libtest", funcidx),
                                kind="libtest", generated=False)
    programs["lib1521"] = {"file": "tests/libtest/mk-lib1521.pl (generates lib1521.c from include/curl/curl.h)",
                           "kind": "libtest", "generated": True, "entry": [], "includes": [],
                           "curl_api_calls": [], "curl_symbols": []}
    for f in unit_files:
        programs[f[:-2]] = dict(analyze_c_test(TESTS / "unit" / f, "unit", funcidx),
                                kind="unit", generated=False)
    for f in tunit_files:
        programs[f[:-2]] = dict(analyze_c_test(TESTS / "tunit" / f, "tunit", funcidx),
                                kind="tunit", generated=False)
    for name, pr in programs.items():
        if not pr["generated"]:
            exp = f"test_{name}"
            if exp not in pr["entry"]:
                discrepancies.setdefault("entry_function_mismatch", []).append(
                    {"program": name, "found": pr["entry"]})

    # tool usage
    users = collections.defaultdict(list)
    for t in tests:
        if t["tool_name"]:
            users[t["tool_name"]].append(t["number"])
    for name, pr in programs.items():
        pr["tests"] = sorted(users.get(name, []))
    discrepancies["tool_without_program"] = sorted(
        {n for n in users if n not in programs})
    discrepancies["tool_resolution_failed"] = sorted(
        t["number"] for t in tests if t["runner"] == "unresolvable")
    discrepancies["programs_without_test"] = sorted(n for n, p in programs.items() if not p["tests"])
    discrepancies["tests_with_unittest_keyword_without_program"] = sorted(
        t["number"] for t in tests if t["runner"] in ("unit", "tunit", "libtest")
        and t["tool_name"] not in programs)
    # libtest/unit-ish keywords vs runner agreement
    discrepancies["keyword_runner_mismatch"] = sorted(
        t["number"] for t in tests
        if (("unittest" in t["keywords"]) != (t["runner"] == "unit")) or
           (("tunittest" in t["keywords"]) != (t["runner"] == "tunit")))

    # perl/shell scripts invoked
    helper_scripts = sorted(p.name for p in TESTS.glob("test*.pl")) + \
        sorted(p.name for p in (TESTS / "libtest").glob("test*.pl"))
    script_users = {}
    for s in sorted(set(helper_scripts)):
        users_s = [t["number"] for t in tests if re.search(re.escape(s), t["command"])]
        script_users[s] = users_s

    # --------------------------------------------------------------- pytest
    py = parse_pytests()
    fixtures = parse_conftest_fixtures()
    n_py = 0
    for m in py:
        for c in m["classes"]:
            n_py += len(c["tests"])
        n_py += len(m["functions"])
    # independent count: text scan of "def test_" at any indent
    indep_py = sum(len(re.findall(r"^\s*def (test_\w+)\(", (TESTS / "http" / pathlib.Path(m["file"]).name).read_text(), re.MULTILINE))
                   for m in py)
    check(indep_py == n_py, f"pytest function count: ast {n_py} != regex {indep_py}")
    check(n_py > 300, "implausibly few pytest functions")
    first_py = py[0]["classes"][0]["tests"][0]["name"]
    check(first_py == "test_01_01_http_get", f"first pytest is {first_py}")
    py_files_listed = sorted(p.name for p in (TESTS / "http").glob("test_*.py"))
    check([pathlib.Path(m["file"]).name for m in py] == py_files_listed, "pytest files not all consumed")
    src(TESTS / "http" / "testenv" / "env.py")
    pytest_support = sorted(rel(p) for p in (TESTS / "http" / "testenv").rglob("*") if p.is_file()
                            and "__pycache__" not in p.parts)
    other_http = sorted(p.name for p in (TESTS / "http").iterdir()
                        if p.is_file() and not p.name.startswith("test_"))

    # -------------------------------------------------------------- servers
    c_servers = {}
    for p in sorted((TESTS / "server").glob("*.c")):
        if p.name in ("first.c", "util.c", "getpart.c"):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        src(p)
        c_servers[p.stem] = {
            "file": rel(p),
            "entry": sorted(set(re.findall(r"^static int (test_\w+)\s*\(", text, re.MULTILINE))),
            "long_options": sorted(set(re.findall(r'"--([a-z][a-z0-9-]*)"', text))),
        }
    srv_inc = read_makefile_inc_list(TESTS / "server" / "Makefile.inc")
    check(sorted(f[:-2] for f in srv_inc) == sorted(c_servers), "server programs vs Makefile.inc")
    for name, rec in c_servers.items():
        check(rec["entry"] == [f"test_{name}"], f"server {name} entry {rec['entry']}")

    # keywords the harness knows how to start
    spm = (TESTS / "servers.pm").read_text()
    src(TESTS / "servers.pm")
    start = spm[spm.index("sub startservers"):spm.index("sub stopservers")]
    harness_keywords = set(re.findall(r'\$what eq "([a-z0-9/-]+)"', start))
    harness_keywords |= set(re.findall(r"\$what eq '([a-z0-9/-]+)'", start))
    m = re.search(r"\$what =~ /\^\(([a-z0-9|]+)\)s\$/", start)
    check(m, "servers.pm: pingpong-tls regex not found")
    harness_keywords |= {f"{x}s" for x in m.group(1).split("|")}
    harness_keywords |= {"pop3", "ftp", "imap", "smtp", "https-mtls"}  # from `||` chains
    discrepancies["server_map_vs_servers_pm"] = {
        "in_servers_pm_not_in_map": sorted(harness_keywords - set(SERVER_MAP)),
        "in_map_not_in_servers_pm": sorted(set(SERVER_MAP) - harness_keywords),
    }
    # verify driver files mention the programs
    for drv, progs, _ext, _note in SERVER_MAP.values():
        if drv:
            check((ROOT / drv).exists(), f"server driver {drv} missing")
            src(ROOT / drv)
        for pr in progs:
            check(pr in c_servers, f"server program {pr} not built from tests/server")
    driver_text = {d: (ROOT / d).read_text() for d in
                   {v[0] for v in SERVER_MAP.values() if v[0]}}
    prog_in_driver = {"tests/http-server.pl": "sws", "tests/rtspserver.pl": "rtspd",
                      "tests/tftpserver.pl": "tftpd", "tests/ftpserver.pl": "sockfilt"}
    for d, prog in prog_in_driver.items():
        check(f"'{prog}'" in driver_text[d], f"{d} does not launch {prog}")
    for prog in ("dnsd", "mqttd", "socksd"):
        check(f"server_exe('{prog}')" in driver_text["tests/servers.pm"], f"servers.pm does not launch {prog}")
    check("nghttpx" in driver_text["tests/http2-server.pl"] and "nghttpx" in driver_text["tests/http3-server.pl"],
          "nghttpx drivers")
    check("stunnel" in driver_text["tests/secureserver.pl"], "secureserver.pl/stunnel")
    check("sshd" in (ROOT / "tests/sshserver.pl").read_text(), "sshserver.pl/sshd")

    # which keywords do tests use?
    def norm_server(line):
        parts = line.split()
        return parts[0].lower(), (parts[1] if len(parts) > 1 else None)
    used_servers = collections.defaultdict(list)
    used_certs = collections.defaultdict(set)
    for t in tests:
        names = set()
        for l in t["servers"]:
            n, cert = norm_server(l)
            names.add(n)
            if cert:
                used_certs[n].add(cert)
        t["server_names"] = sorted(names)
        for n in names:
            used_servers[n].append(t["number"])
        kn = set()
        for l in t["killserver"]:
            kn.add(norm_server(l)[0])
        t["killserver_names"] = sorted(kn)
    discrepancies["server_keyword_unknown_to_map"] = sorted(set(used_servers) - set(SERVER_MAP))
    discrepancies["killserver_keyword_unknown_to_map"] = sorted(
        {n for t in tests for n in t["killserver_names"]} - set(SERVER_MAP))
    discrepancies["map_keyword_unused_by_tests"] = sorted(set(SERVER_MAP) - set(used_servers) - {"dns"})

    # tests needing a server through variables but with no <server>?
    port_var_server = {
        "HTTPPORT": "http", "HTTP6PORT": "http-ipv6", "HTTPSPORT": "https",
        "HTTPSPROXYPORT": "https-proxy", "PROXYPORT": "http-proxy", "FTPPORT": "ftp",
        "FTP6PORT": "ftp-ipv6", "FTPSPORT": "ftps", "SMTPPORT": "smtp", "POP3PORT": "pop3",
        "IMAPPORT": "imap", "TFTPPORT": "tftp", "RTSPPORT": "rtsp", "SSHPORT": "sftp/scp",
        "SOCKSPORT": "socks4/5", "MQTTPORT": "mqtt", "TELNETPORT": "telnet", "DICTPORT": "dict",
        "GOPHERPORT": "gopher", "HTTP2PORT": "http/2", "HTTPTLSPORT": "http (tls)",
        "HTTPUNIXPATH": "http-unix", "SOCKSUNIXPATH": "socks5unix",
    }
    no_server_with_port_var = sorted(
        t["number"] for t in tests if not t["servers"] and
        (set(t["variables"]) & {"HTTPPORT", "FTPPORT", "SMTPPORT", "POP3PORT", "IMAPPORT",
                                "TFTPPORT", "RTSPPORT"}) and t["runner"] != "perl-script")
    discrepancies["port_variable_without_server_section"] = no_server_with_port_var

    # ---------------------------------------------------------------- features
    rt = (TESTS / "runtests.pl").read_text()
    src(TESTS / "runtests.pl")
    literal_feats = set(re.findall(r'\$feature\{"([^"$]+)"\}', rt))
    # protocol names from the harness list of known protocols come from `curl -V`
    all_feats = collections.Counter()
    for t in tests:
        for f in t["features"]:
            all_feats[f.lstrip("!")] += 1
    cond_feats = [t["number"] for t in tests if any(l.startswith("%") for l in t["features"])]
    feat_known = {f: (f in literal_feats) for f in all_feats}
    # features that runtests doesn't set literally come from curl -V / curlinfo ON-lines / protocols
    dynamic_feats = sorted(f for f, k in feat_known.items() if not k)

    # ------------------------------------------------------------ aggregates
    kw_count = collections.Counter(k for t in tests for k in t["keywords"])
    feat_req = collections.Counter(f for t in tests for f in t["features"] if not f.startswith("!"))
    feat_neg = collections.Counter(f[1:] for t in tests for f in t["features"] if f.startswith("!"))
    srv_count = {k: len(v) for k, v in used_servers.items()}
    runner_count = collections.Counter(t["runner"] for t in tests)
    no_server_count = sum(1 for t in tests if not t["servers"])
    attr_count = collections.Counter(v for t in tests for v in t["attr_values"])
    part_count = collections.Counter(p for t in tests for p in t["parts"])
    macro_count = collections.Counter(m for t in tests for m in t["macros"])
    setenv_count = collections.Counter(v for t in tests for v in t["setenv"])
    err_count = collections.Counter()
    for t in tests:
        if t["errorcode"] is not None:
            for c in re.split(r"[,\s]+", t["errorcode"]):
                if c:
                    err_count[c] += 1
    var_count = collections.Counter(v for t in tests for v in t["variables"])
    opt_count = collections.Counter(t["command_option"] for t in tests if t["command_option"])
    type_count = collections.Counter(t["command_type"] for t in tests if t["command_type"])

    # sanity positive controls on aggregates
    check(sum(runner_count.values()) == n_files, "runner counts do not sum to file count")
    check(kw_count["HTTP"] > 100 and kw_count["unittest"] == sum(1 for t in tests if t["runner"] == "unit"),
          "keyword aggregate controls")
    check(srv_count.get("http", 0) > 500, "http server count implausible")
    check(feat_req.get("unittest", 0) >= len(unit_files) - 10, "unittest feature requirement count implausible")
    check(1 in used_servers["http"], "test1 not counted under http")

    problems = {t["number"]: t["problems"] for t in tests if t["problems"]}
    discrepancies["test_file_problems"] = problems
    discrepancies["tests_without_keywords"] = nokw
    discrepancies["tests_with_mixed_eol"] = sorted(t["number"] for t in tests if t["eol"] == "mixed")
    discrepancies["tests_with_crlf_file"] = sorted(t["number"] for t in tests if t["eol"] == "crlf")
    discrepancies["tests_with_non_ascii_bytes"] = sorted(t["number"] for t in tests if t["non_ascii"])
    discrepancies["tests_with_nul_bytes"] = sorted(t["number"] for t in tests if t["nul"])
    discrepancies["features_conditional_lines"] = cond_feats
    check(not problems, f"test files with structural problems: {problems}")

    # which tests run in a default run (before conditional DISABLED/feature skips)
    default_run = sorted(set(bynum) - set(disabled_uncond))

    # ----------------------------------------------------------------- data
    py_flat = []
    for m in py:
        for c in m["classes"]:
            py_flat.extend((m["file"], c["name"], c["decorators"], f) for f in c["tests"])
        py_flat.extend((m["file"], None, [], f) for f in m["functions"])
    skip_conds = collections.Counter()
    fix_count = collections.Counter()
    per_file = collections.Counter()
    for fl, _cls, cdecs, f in py_flat:
        per_file[fl] += 1
        for d in cdecs + f["decorators"]:
            if d.get("kind") == "skipif":
                skip_conds[d["condition"]] += 1
        for fx in f["fixtures"]:
            fix_count[fx] += 1
    check(sum(per_file.values()) == n_py, "pytest per-file sum")

    data = {
        "counts": {
            "test_files": n_files,
            "default_run_candidates": len(default_run),
            "disabled_unconditional": len(disabled_uncond),
            "disabled_entries": len(d_entries),
            "disabled_conditional_only": len(set(disabled_any) - set(disabled_uncond)),
            "libtest_programs": sum(1 for p in programs.values() if p["kind"] == "libtest"),
            "unit_programs": len(unit_files),
            "tunit_programs": len(tunit_files),
            "pytest_functions": n_py,
            "c_server_programs": len(c_servers),
            "server_keywords_mapped": len(SERVER_MAP),
        },
        "runner_counts": dict(sorted(runner_count.items())),
        "keyword_counts": dict(sorted(kw_count.items())),
        "feature_required_counts": dict(sorted(feat_req.items())),
        "feature_forbidden_counts": dict(sorted(feat_neg.items())),
        "features_set_literally_by_runtests": sorted(literal_feats),
        "features_used_but_dynamic": dynamic_feats,
        "server_counts": dict(sorted(srv_count.items())),
        "server_certs_requested": {k: sorted(v) for k, v in sorted(used_certs.items())},
        "tests_without_server_section": no_server_count,
        "part_counts": dict(sorted(part_count.items())),
        "attribute_value_counts": dict(sorted(attr_count.items())),
        "macro_counts": dict(sorted(macro_count.items())),
        "setenv_counts": dict(sorted(setenv_count.items())),
        "errorcode_counts": dict(sorted(err_count.items(), key=lambda kv: (len(kv[0]), kv[0]))),
        "variable_counts": dict(sorted(var_count.items())),
        "command_option_counts": dict(sorted(opt_count.items())),
        "command_type_counts": dict(sorted(type_count.items(), key=lambda kv: str(kv[0]))),
        "tests": [
            {k: t[k] for k in (
                "number", "name", "keywords", "features", "servers", "server_names", "killserver",
                "tool", "tool_name", "runner", "has_command", "command", "command_type",
                "command_option", "setenv", "has_precheck", "precheck", "errorcode", "postcheck",
                "disable", "parts", "attr_values", "macros", "variables", "eol", "non_ascii",
                "nul", "bytes")}
            for t in tests],
        "disabled": {"entries": d_entries, "directives": d_directives,
                     "non_comment_lines": d_noncomment,
                     "unconditional": disabled_uncond, "duplicated_entries": dup},
        "makefile_am": {"testcases_listed": len(mk_nums), "extra_dist": extra_files},
        "data_dir_other_files": other_files,
        "programs": {k: programs[k] for k in sorted(programs)},
        "helper_perl_scripts": script_users,
        "pytest": {
            "files": py,
            "conftest_fixtures": fixtures,
            "skip_condition_counts": dict(sorted(skip_conds.items())),
            "fixture_usage_counts": dict(sorted(fix_count.items())),
            "tests_per_file": dict(sorted(per_file.items())),
            "other_files_in_tests_http": other_http,
            "testenv_files": pytest_support,
        },
        "servers": {
            "c_programs": c_servers,
            "keyword_map": {k: {"driver": v[0], "c_programs": v[1], "external": v[2], "note": v[3]}
                            for k, v in sorted(SERVER_MAP.items())},
            "harness_scripts": sorted(rel(p) for p in TESTS.iterdir()
                                      if p.is_file() and re.search(r"(server|dictserver)", p.name)
                                      and p.suffix in (".pl", ".py")),
            "python_servers": sorted(p.name for p in TESTS.glob("*.py")),
            "port_variable_hints": port_var_server,
        },
        "doc_claims": doc_claims,
        "discrepancies": discrepancies,
    }

    sample_failed = [k for k, v in discrepancies.items()
                     if k in ("makefile_am_without_file", "tool_without_program",
                              "tool_resolution_failed", "server_keyword_unknown_to_map",
                              "killserver_keyword_unknown_to_map") and v]
    check(not sample_failed, f"hard discrepancies: { {k: discrepancies[k] for k in sample_failed} }")

    summary = render_md(data, tests, programs, py_flat, SERVER_MAP, d_entries, d_directives,
                        used_servers, discrepancies, script_users, c_servers, dynamic_feats)
    common.write("tests", data, summary, sources)
    print(f"tests: {n_files} test files, {n_py} pytest functions, {len(programs)} programs")


def top(counter_dict, n=None):
    items = sorted(counter_dict.items(), key=lambda kv: (-kv[1], kv[0]))
    return items[:n] if n else items


def render_md(data, tests, programs, py_flat, SERVER_MAP, d_entries, d_directives,
              used_servers, disc, script_users, c_servers, dynamic_feats):
    c = data["counts"]
    out = []
    emit = out.append
    emit("# C test suite inventory\n")
    emit(
        "The tests the rewrite is scored on: `tests/data/testNNNN` driven by `tests/runtests.pl`, "
        "the libtest/unit/tunit C programs they invoke, the `tests/http` pytest suite and the test "
        "servers. Parsed with a port of `tests/getpart.pm` (line based, bytes read as latin-1, "
        "CRLF folded as `runtests.pl` does). `runtests.pl` finds tests by listing `tests/data` for "
        "`^test[0-9]+$` files and subtracting `tests/data/DISABLED`; `tests/data/Makefile.am` is only "
        "checked for a warning. Full per-test records are in `tests.json`.\n")
    emit("## Counts\n")
    emit(md_table(["what", "count"], [
        ("test files (`tests/data/test*`)", c["test_files"]),
        ("unconditionally DISABLED", c["disabled_unconditional"]),
        ("DISABLED only under a condition", c["disabled_conditional_only"]),
        ("tests in a default run before feature/server skips", c["default_run_candidates"]),
        ("libtest programs (incl. generated lib1521)", c["libtest_programs"]),
        ("unit programs (`tests/unit`)", c["unit_programs"]),
        ("tunit programs (`tests/tunit`)", c["tunit_programs"]),
        ("pytest functions (`tests/http/test_*.py`, before parametrization)", c["pytest_functions"]),
        ("C test server programs (`tests/server`)", c["c_server_programs"]),
        ("tests with no `<server>` section", data["tests_without_server_section"]),
    ]))
    emit("\n## Tests by runner\n")
    emit("`curl` runs the curl tool; `libtest`/`unit`/`tunit` run the named C program; "
               "`perl-script`/`shell-script` are `<command type=...>`.\n")
    emit(md_table(["runner", "tests"], sorted(data["runner_counts"].items())))
    emit("\n## Tests per server keyword\n")
    emit(md_table(["server", "tests"], top(data["server_counts"])))
    emit("\n## Required features (`<features>`, positive)\n")
    emit("Feature names set literally in `runtests.pl` are marked `L`; others come from the "
               "`curl -V` feature/protocol list or the build-config ON/OFF list (`D`).\n")
    lit = set(data["features_set_literally_by_runtests"])
    emit(md_table(["feature", "tests", "source"],
                        [(f, n, "L" if f in lit else "D") for f, n in top(data["feature_required_counts"])]))
    emit("\n## Forbidden features (`!feature`)\n")
    emit(md_table(["feature", "tests"], top(data["feature_forbidden_counts"])))
    emit("\n## Tests per keyword\n")
    emit(md_table(["keyword", "tests"], top(data["keyword_counts"])))
    emit("\n## Expected exit codes (`<verify><errorcode>`)\n")
    emit(md_table(["code", "tests"], top(data["errorcode_counts"])))
    emit("\n## `<setenv>` variables\n")
    emit(md_table(["variable", "tests"], top(data["setenv_counts"])))
    emit("\n## Test file sections\n")
    emit(md_table(["section/part", "tests"], top(data["part_counts"])))
    emit("\n## Attribute values on sections (mode attributes)\n")
    emit(md_table(["attr=value", "tests"], top(data["attribute_value_counts"])))
    emit("\n## Preprocessor macros used\n")
    emit(md_table(["macro", "tests"], top(data["macro_counts"])))
    emit("\n## `<command option=...>` and `type=`\n")
    emit(md_table(["option", "tests"], top(data["command_option_counts"])))
    emit(md_table(["type", "tests"], list(data["command_type_counts"].items())))
    emit("\n## DISABLED\n")
    emit(f"Non-comment lines: {data['disabled']['non_comment_lines']} "
               f"({len(d_entries)} test entries + {len(d_directives)} "
               "`%if`/`%else`/`%endif` directives).\n")
    emit(md_table(["test", "conditions", "name", "comment"],
                        [(e["test"], " & ".join(e["conditions"]) or "-",
                          next(t["name"] for t in tests if t["number"] == e["test"]),
                          e.get("comment") or "") for e in d_entries]))

    # programs
    emit("\n## libtest programs\n")
    emit("`first.c` dispatches by program name, so every libtest is one entry in the "
               "`libtests` bundle. `API` is the number of distinct `curl_*()` functions called; "
               "`syms` the number of distinct `CURL*_*` constants referenced.\n")
    rows = []
    for k in sorted(programs):
        p = programs[k]
        if p["kind"] != "libtest":
            continue
        rows.append((k, ",".join(map(str, p["tests"])) or "-", len(p["curl_api_calls"]),
                     len(p["curl_symbols"]), "generated" if p["generated"] else ""))
    emit(md_table(["program", "tests", "API", "syms", ""], rows))

    emit("\n## unit programs (link libcurl internals)\n")
    emit("`files` are the lib/ sources defining the non-static functions the test calls "
               "(function name match; a name defined in several files lists them all). "
               "Full function lists are in the JSON.\n")
    rows = []
    for k in sorted(programs):
        p = programs[k]
        if p["kind"] != "unit":
            continue
        rows.append((k, ",".join(map(str, p["tests"])) or "-",
                     ", ".join(f.replace("lib/", "") for f in p["exercises_files"]) or "-",
                     len(p["internal_functions"])))
    emit(md_table(["program", "tests", "files", "#fn"], rows))
    emit("\n## tunit programs (link curl tool internals)\n")
    rows = []
    for k in sorted(programs):
        p = programs[k]
        if p["kind"] != "tunit":
            continue
        rows.append((k, ",".join(map(str, p["tests"])) or "-",
                     ", ".join(f.replace("src/", "") for f in p["exercises_files"]) or "-",
                     ", ".join(sorted(p["internal_functions"])) or "-",
                     "Windows/DOS only" if p.get("platform_conditional") else ""))
    emit(md_table(["program", "tests", "files", "functions", "note"], rows))

    # helper scripts
    emit("\n## Perl helper scripts invoked from test commands\n")
    emit(md_table(["script", "tests"], [(k, ",".join(map(str, v)) or "-") for k, v in script_users.items()]))

    # pytest
    emit("\n## pytest suite (`tests/http`)\n")
    emit(md_table(["file", "functions"], list(data["pytest"]["tests_per_file"].items())))
    emit("\nSkip conditions (count of decorators across functions and classes):\n")
    emit(md_table(["condition", "uses"], top(data["pytest"]["skip_condition_counts"])))
    emit("\nFixture usage (test function arguments):\n")
    emit(md_table(["fixture", "tests"], top(data["pytest"]["fixture_usage_counts"])))
    emit("\nSession fixtures in `conftest.py`: " + ", ".join(
        f["name"] for f in data["pytest"]["conftest_fixtures"]) + "\n")
    emit("\nFiles in `tests/http/testenv` (server wrappers and client driver): " +
               ", ".join(pathlib.Path(x).name for x in data["pytest"]["testenv_files"]) + "\n")
    emit("\nTest functions:\n")
    rows = []
    for fl, cls, cdecs, f in py_flat:
        sk = [d["condition"] for d in cdecs + f["decorators"] if d.get("kind") == "skipif"]
        pm = [f"{d['argnames']}x{d['n_values'] if d['n_values'] is not None else '?'}"
              for d in cdecs + f["decorators"] if d.get("kind") == "parametrize"]
        rows.append((pathlib.Path(fl).name, cls or "-", f["name"], "; ".join(pm), "; ".join(sk)))
    emit(md_table(["file", "class", "test", "parametrize", "skipif"], rows))

    # servers
    emit("\n## Test servers\n")
    emit("C programs in `tests/server`, all built into one `servers` bundle and launched as "
               "`servers <name>` by the Perl drivers or by `servers.pm` directly:\n")
    emit(md_table(["program", "file", "long options"],
                        [(k, v["file"], ", ".join("--" + o for o in v["long_options"]))
                         for k, v in c_servers.items()]))
    emit("\nServer keyword (`<server>`) to implementation, from `servers.pm`:\n")
    emit(md_table(["keyword", "tests", "driver", "C programs", "external", "note"],
                        [(k, len(used_servers.get(k, [])), v[0] or "-", ", ".join(v[1]) or "-",
                          ", ".join(v[2]) or "-", v[3]) for k, v in sorted(SERVER_MAP.items())]))

    # discrepancies
    emit("\n## Cross-checks and discrepancies\n")
    rows = []
    for k, v in disc.items():
        if isinstance(v, dict):
            v = {a: b for a, b in v.items() if b}
        s = json.dumps(v) if v else "none"
        if len(s) > 160:
            s = s[:157] + "..."
        rows.append((k, s))
    emit(md_table(["check", "result"], rows))
    emit("\nFeatures used by tests that `runtests.pl` does not set literally (protocols or "
               "`curl -V` names): " + ", ".join(dynamic_feats) + "\n")
    return "\n".join(out)


if __name__ == "__main__":
    main()
