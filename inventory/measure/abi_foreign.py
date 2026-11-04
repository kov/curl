"""
Measure the libcurl C ABI for a target other than the host's.

`inventory/gen/abi.py` measures the host's target with gcc. The scripts
beside this one (`abi_msvc.py`, `abi_darwin.py`) measure the same names
for another target, on a machine of that target, with its own compiler:
the declarations of the typedefs and structs as its preprocessor leaves
them, and the probe's sizes, alignments, offsets, bit positions and
constant values as it computes them. The names come from
`inventory/abi.json`; a name that parses differently there, or a typedef,
struct, enum or function set that differs, fails the run. Each writes
`inventory/abi-<target>.json` (and `.md`, what differs from the host),
which `gen/ffi.py` reads.

`abi.py` fails while a target's `probe-key` no longer matches the headers
and the probe, so a header change cannot leave a measurement stale unseen.
"""

import json
import pathlib
import re
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gen"))
import abi
import common
from common import check


def measure(target, title, compiler, version, preprocess, measured_by,
            generated_by, controls):
    """
    Measure `target` with `compiler` (as `abi.run_probe` drives one) and
    write its inventory. `preprocess(scratch)` returns the public headers'
    preprocessed code by header; `controls(values, sizes, structs)` checks
    what must hold on this target, so a probe that ran the wrong compiler
    or headers fails.
    """
    name = f"abi-{target}"
    host = json.loads((common.INVENTORY / "abi.json").read_text())
    check(host["c-commit"] == common.c_commit(),
          f"abi.json is from C commit {host['c-commit']}, this checkout is "
          f"at {common.c_commit()}")
    host = host["data"]
    with tempfile.TemporaryDirectory(prefix=f"inventory-{name}-") as tmp:
        abi.SCRATCH = pathlib.Path(tmp)
        code = preprocess(abi.SCRATCH)
        lines = abi.foreign_probe_lines(host)
        out, dropped = abi.run_probe(lines, compiler)
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

    # Positive controls: values that hold on every target, then the
    # target's own.
    v = {c["name"]: c["value"] for c in constants}
    check(v["CURLE_OK"] == "0" and v["CURLOPT_URL"] == "10002",
          "CURLcode and CURLOPT values")
    controls(v, sizes, structs)

    data = {
        "target": target,
        "compiler": version,
        "measured-by": measured_by,
        "probe-key": abi.probe_key(lines),
        "probe-dropped": sorted(dropped),
        "constants": constants,
        "enums": [{"typedef": e["typedef"], "tag": e["tag"],
                   "size": e["size"]} for e in enums],
        "structs": dict(sorted(structs.items())),
        "typedefs": sorted(typedefs, key=lambda t: t["name"]),
    }
    common.write(name, data, summary(host, data, title, generated_by, name),
                 ["include/curl/"], generated_by=generated_by)


def summary(host, data, title, generated_by, name):
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
        # The compilers' attributes and the preprocessors' spacing are not
        # part of the type. A type a compiler cannot size (void, a function
        # type: gcc says 1, an extension) is listed with the dropped probe
        # lines below.
        return (spelling(t["decl"]) != spelling(h["decl"]) or
                (t["size"] is not None and
                 (t["size"], t["align"]) != (h["size"], h["align"])))
    tdefs = [(t["name"], f"`{ht[t['name']]['decl']}`",
              ht[t["name"]]["size"], f"`{t['decl']}`", t["size"])
             for t in data["typedefs"] if differs(t, ht[t["name"]])]
    md = [f"# libcurl ABI on {title}\n",
          (f"Measured with {data['compiler']} for `{data['target']}` by "
           f"`{generated_by}`, for the names `abi.json` "
           f"holds. Host target: `{host['target']}`. Only what differs "
           "from the host is listed here; the rest is in "
           f"`{name}.json`.\n"),
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
