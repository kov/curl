#!/usr/bin/env python3
"""
Measure the libcurl C ABI for x86_64 Windows with MSVC.

`inventory/gen/abi.py` measures the host's target with gcc. This measures
the same names for x86_64-pc-windows-msvc: the declarations of the
typedefs and structs as MSVC's preprocessor leaves them (`_WIN32` and
`_MSC_VER` defined by the compiler itself), and the probe's sizes,
alignments, offsets, bit positions and constant values as `cl` computes
them. The names come from `inventory/abi.json`; a name that parses
differently here, or a typedef, struct, enum or function set that differs,
fails the run. The result is `inventory/abi-x86_64-pc-windows-msvc.json`
(and `.md`, what differs from the host), which `gen/ffi.py` reads.

It runs on Windows, in a checkout at the C commit `abi.json` was made
from, under MSYS2's python3 inside a Visual Studio developer environment:

    cmd //c 'inventory\\measure\\abi_msvc.bat'

`abi.py` fails while this file's `probe-key` no longer matches the
headers and the probe, so a header change cannot leave it stale unseen.
"""

import json
import pathlib
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gen"))
import abi
import common
from common import ROOT, check

TARGET = "x86_64-pc-windows-msvc"
NAME = f"abi-{TARGET}"
MEASURED_BY = "inventory/measure/abi_msvc.bat on Windows"


def winpath(path):
    """`path` as cl reads it: MSYS2 passes POSIX paths unconverted here."""
    return subprocess.run(["cygpath", "-m", str(path)], check=True,
                          capture_output=True, text=True).stdout.strip()


# Options are spelled with `-`: MSYS2 rewrites arguments starting with `/`
# into paths before cl sees them.
CFLAGS = ["-nologo", "-std:c11", "-I", winpath(ROOT / "include"),
          "-DCURL_DISABLE_TYPECHECK"]


def cl(args, cwd):
    return subprocess.run(["cl", *CFLAGS, *args], check=False, cwd=cwd,
                          capture_output=True, text=True)


class Msvc:
    """cl, as abi.run_probe drives a compiler."""

    diagnostic = re.compile(r"probe\.c\((\d+)\): (?:fatal )?error\b")

    def build(self, src, scratch):
        # A pointer handed to the probe's integer printer is an error, as
        # gcc's -Werror=int-conversion makes it: C4047 (levels of
        # indirection) and C4024 (argument type). C4996 is a deprecation.
        r = cl(["-we4047", "-we4024", "-wd4996", "-Feprobe.exe", src.name],
               scratch)
        # cl prints its diagnostics on stdout.
        return r.returncode, r.stdout + r.stderr, scratch / "probe.exe"


def compiler_version():
    r = subprocess.run(["cl"], check=False, capture_output=True, text=True)
    m = re.search(r"Compiler Version (\S+) for (\S+)", r.stderr)
    check(m is not None, f"no cl version in {r.stderr!r}")
    check(m.group(2) == "x64", f"cl targets {m.group(2)}, not x64")
    return m.group(1)


def preprocess(scratch):
    """Return the public headers' preprocessed code, by header."""
    src = scratch / "pp.c"
    src.write_text("#include <curl/curl.h>\n")
    r = cl(["-E", src.name], scratch)
    check(r.returncode == 0, f"preprocessing failed: {r.stdout}{r.stderr}")
    include = winpath(ROOT / "include/curl").lower() + "/"
    code, cur = {}, None
    for line in r.stdout.splitlines():
        m = re.match(r'^#line \d+ "(.*)"', line)
        if m:
            p = m.group(1).replace("\\\\", "/").replace("\\", "/")
            cur = p[len(include):] if p.lower().startswith(include) else None
            continue
        if cur is None or line.startswith("#pragma"):
            continue
        # CURL_EXTERN: the linkage of a declaration, not its type.
        code.setdefault(cur, []).append(
            line.replace("__declspec(dllimport)", ""))
    return {h: "\n".join(v) for h, v in code.items()}


def main():
    host = json.loads((common.INVENTORY / "abi.json").read_text())
    check(host["c-commit"] == common.c_commit(),
          f"abi.json is from C commit {host['c-commit']}, this checkout is "
          f"at {common.c_commit()}")
    host = host["data"]
    version = compiler_version()
    with tempfile.TemporaryDirectory(prefix="inventory-abi-msvc-") as tmp:
        abi.SCRATCH = pathlib.Path(tmp)
        code = preprocess(abi.SCRATCH)
        lines = abi.foreign_probe_lines(host)
        out, dropped = abi.run_probe(lines, Msvc())
    funcs, enums, structs, typedefs, opaque = abi.parse_code(code)

    # The same names as the host, or the probe lines measure something else.
    def names(items, key):
        return sorted(key(i) for i in items)
    check(names(funcs, lambda f: f["name"]) ==
          names(host["functions"], lambda f: f["name"]), "function set")
    for f in funcs:
        h = next(g for g in host["functions"] if g["name"] == f["name"])
        check(f["prototype"] == h["prototype"],
              f"prototype of {f['name']}: {f['prototype']!r}")
    check(names(typedefs, lambda t: t["name"]) ==
          names(host["typedefs"], lambda t: t["name"]), "typedef set")
    check(opaque == host["opaque-types"], "opaque types")
    check(sorted(structs) == sorted(host["structs"]), "struct set")
    for s, info in structs.items():
        check([f["name"] for f in info["fields"]] ==
              [f["name"] for f in host["structs"][s]["fields"]],
              f"fields of {s}")
    check([(e["typedef"], e["tag"], [m["name"] for m in e["members"]])
           for e in enums] ==
          [(e["typedef"], e["tag"], e["members"]) for e in host["enums"]],
          "enums")

    values, sizes, offsets, bitpos = {}, {}, {}, {}
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
    for s, info in structs.items():
        for f in info["fields"]:
            if f["decl"].endswith("{...}"):
                continue
            if "bit-width" in f:
                check((s, f["name"]) in bitpos, f"no bit position for "
                      f"{s}.{f['name']}")
                f["offset"], f["bit"] = bitpos[s, f["name"]]
                continue
            check((s, f["name"]) in offsets, f"no offset for {s}.{f['name']}")
            f["offset"], f["size"] = offsets[s, f["name"]]
        check(s in sizes, f"no size for {s}")
        info.update(sizes[s])
    for t in typedefs:
        t.update(sizes.get(t["name"], {"size": None, "align": None}))
        t.pop("deprecated", None)
    for e in enums:
        e["size"] = sizes.get(e["typedef"] or f"enum {e['tag']}",
                              {}).get("size")
        check(e["size"] is not None, f"no size for {e['typedef'] or e['tag']}")
    constants = []
    for c in host["constants"]:
        rec = {"name": c["name"], **values.get(
            c["name"], {"c-type": None, "value": None})}
        check(c["kind"] == "macro" or rec["value"] is not None,
              f"enum constant {c['name']} did not evaluate")
        constants.append(rec)

    # Positive controls: values that hold on every target, and the ones
    # that make this LLP64 rather than the host's LP64.
    v = {c["name"]: c["value"] for c in constants}
    check(v["CURLE_OK"] == "0" and v["CURLOPT_URL"] == "10002",
          "CURLcode and CURLOPT values")
    check(structs["struct curl_slist"]["size"] == 16, "curl_slist on x64")
    check(sizes["curl_off_t"]["size"] == 8 and
          sizes["curl_socket_t"]["size"] == 8, "curl_off_t, SOCKET")
    check(next(f for f in structs["struct curl_fileinfo"]["fields"]
               if f["name"] == "hardlinks")["size"] == 4, "LLP64 long")

    data = {
        "target": TARGET,
        "compiler": f"cl {version}",
        "measured-by": MEASURED_BY,
        "probe-key": abi.probe_key(lines),
        "probe-dropped": sorted(dropped),
        "constants": constants,
        "enums": [{"typedef": e["typedef"], "tag": e["tag"],
                   "size": e["size"]} for e in enums],
        "structs": dict(sorted(structs.items())),
        "typedefs": sorted(typedefs, key=lambda t: t["name"]),
    }
    common.write(NAME, data, summary(host, data), ["include/curl/"],
                 generated_by="inventory/measure/abi_msvc.py")


def summary(host, data):
    """Summarise what differs from the host's measurement."""
    hv = {c["name"]: c for c in host["constants"]}
    consts = [(c["name"], hv[c["name"]]["c-type"], hv[c["name"]]["value"],
               c["c-type"], c["value"]) for c in data["constants"]
              if (c["c-type"], c["value"]) !=
              (hv[c["name"]].get("c-type"), hv[c["name"]].get("value"))]
    ht = {t["name"]: t for t in host["typedefs"]}

    def spelling(decl):
        return re.sub(r"\s+", "", abi.strip_attrs(decl)[0])

    def differs(t, h):
        # gcc's attributes and the preprocessors' spacing are not part of
        # the type. A type cl cannot size (void, a function type: gcc says
        # 1, an extension) is listed with the dropped probe lines below.
        return (spelling(t["decl"]) != spelling(h["decl"]) or
                (t["size"] is not None and
                 (t["size"], t["align"]) != (h["size"], h["align"])))
    tdefs = [(t["name"], f"`{ht[t['name']]['decl']}`",
              ht[t["name"]]["size"], f"`{t['decl']}`", t["size"])
             for t in data["typedefs"] if differs(t, ht[t["name"]])]
    md = ["# libcurl ABI on x86_64 Windows (MSVC)\n",
          (f"Measured with {data['compiler']} for `{data['target']}` by "
           "`inventory/measure/abi_msvc.py`, for the names `abi.json` "
           f"holds. Host target: `{host['target']}`. Only what differs "
           "from the host is listed here; the rest is in "
           f"`{NAME}.json`.\n"),
          "## Typedefs\n",
          common.md_table(["typedef", "host", "host size", "here",
                           "size"], tdefs),
          "## Structs\n"]
    for s, info in data["structs"].items():
        h = host["structs"][s]
        rows = []
        for f, g in zip(info["fields"], h["fields"]):
            mine = (f["decl"], f.get("offset"), f.get("size"), f.get("bit"))
            theirs = (g["decl"], g.get("offset"), g.get("size"), g.get("bit"))
            if mine != theirs:
                rows.append((f["name"], g.get("offset", ""),
                             f.get("offset", ""),
                             g.get("size", g.get("bit", "")),
                             f.get("size", f.get("bit", ""))))
        if rows or (info["size"], info["align"]) != (h["size"], h["align"]):
            md += [(f"### `{s}`: size {info['size']} (host {h['size']}), "
                    f"align {info['align']} (host {h['align']})\n"),
                   common.md_table(["field", "host offset", "offset",
                                    "host size or bit", "size or bit"],
                                   rows)]
    md += ["## Constants\n",
           common.md_table(["name", "host type", "host value", "type",
                            "value"], consts)]
    if data["probe-dropped"]:
        md += ["Probe lines that did not compile: "
               + ", ".join(f"`{d}`" for d in data["probe-dropped"]) + "\n"]
    return "\n".join(md)


if __name__ == "__main__":
    main()
