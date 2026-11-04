#!/usr/bin/env python3
"""
Generate src/ffi.rs, the C types of libcurl's public headers, from abi.json.

inventory/abi.json holds what gcc computed from include/curl: constant
values, struct layouts, typedefs and prototypes. inventory/abi-<target>.json
holds the same for another target, measured with its own compiler. This
turns them into Rust declarations for the C ABI shim:

  - C enums become `#[repr(transparent)]` integer newtypes with one constant
    per member, never Rust enums: a value from C may be any integer, and an
    out-of-range Rust enum is undefined behaviour before it can be checked;
  - every struct gets compile-time assertions of its size, alignment and
    field offsets, as each target's compiler measured them, on that target;
  - every public function gets a function-pointer type in `proto`, so an
    exported definition can be checked against its prototype at build time.

A declaration every target renders alike is emitted once; one that differs
(`curl_off_t`, `curl_socket_t`, a struct laid out differently, a constant's
type or value) is emitted per target family, under its cfg.

`--check` exits non-zero instead of writing when ffi.rs is out of date.
"""

import copy
import json
import pathlib
import re

import genlib
from genlib import ABI, ROOT, check

HERE = pathlib.Path(__file__).resolve()
OUT = ROOT / "crates" / "curl-sys-abi" / "src" / "ffi.rs"

WINDOWS = "x86_64-pc-windows-msvc"
# Each measured target: its measurement, the cfg its layout assertions hold
# under (that target only), and the cfg a declaration that differs between
# targets is given (the target's family: x86_64 Linux declares what aarch64
# Linux measured).
TARGETS = [
    (ABI, "aarch64-redhat-linux",
     'all(target_os = "linux", target_arch = "aarch64")',
     'not(target_os = "windows")'),
    (ROOT / "inventory" / f"abi-{WINDOWS}.json", WINDOWS,
     ('all(target_os = "windows", target_arch = "x86_64", '
      'target_env = "msvc")'),
     'target_os = "windows"'),
]

KEYWORDS = {"as", "break", "const", "continue", "crate", "else", "enum",
            "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop",
            "match", "mod", "move", "mut", "pub", "ref", "return", "self",
            "static", "struct", "super", "trait", "true", "type", "unsafe",
            "use", "where", "while", "async", "await", "dyn", "abstract",
            "become", "box", "do", "final", "macro", "override", "priv",
            "typeof", "unsized", "virtual", "yield", "try", "gen"}

SCALARS = {
    "char": "c_char", "signed char": "c_schar", "unsigned char": "c_uchar",
    "short": "c_short", "short int": "c_short",
    "unsigned short": "c_ushort", "int": "c_int", "signed int": "c_int",
    "unsigned": "c_uint", "unsigned int": "c_uint",
    "long": "c_long", "long int": "c_long", "unsigned long": "c_ulong",
    "unsigned long int": "c_ulong", "long long": "c_longlong",
    "unsigned long long": "c_ulonglong", "size_t": "usize",
    "__int64": "i64", "unsigned __int64": "u64",
    "double": "f64", "float": "f32", "void": "c_void",
}
C_TYPE_WORDS = {"char", "short", "int", "long", "unsigned", "signed",
                "double", "float", "void"}


def prelude(target):
    """
    Return the system types the headers use, as `target`'s units.

    Not measured by name: each is checked through the curl types that use
    it, by size (`curl_socket_t`, `curl_socklen_t`) or by the offsets of the
    fields after it (`time_t` in `curl_fileinfo`). Signedness is no layout's
    to check: it is the system headers' spelling (Winsock's `SOCKET` is
    `UINT_PTR`, `socklen_t` an `int`, the CRT's `time_t` `__time64_t`).
    """
    windows = target == WINDOWS
    return [
        ("prelude", [(
            "// System types the headers use. Their layouts are checked below"
            " with the\n// rest, from the sizes the compiler reported for the"
            " curl types that use them.")]),
        ("time_t", [f"pub type time_t = {'i64' if windows else 'c_long'};"]),
        ("socklen_t", [
            f"pub type socklen_t = {'c_int' if windows else 'c_uint'};"]),
        ("SOCKET", ["pub type SOCKET = usize;"] if windows else []),
        ("sockaddr", ["""
#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr {
    pub sa_family: c_ushort,
    pub sa_data: [c_char; 14],
}"""]),
        ("FILE", ["""
/// Only ever behind a pointer.
#[repr(C)]
pub struct FILE {
    _opaque: [u8; 0],
}"""]),
        ("fd_set", ["""
/// Only ever behind a pointer.
#[repr(C)]
pub struct fd_set {
    _opaque: [u8; 0],
}
"""]),
    ]


def ident(name):
    return f"r#{name}" if name in KEYWORDS else name


class Types:
    """Map C type spellings to Rust, given the headers' typedefs."""

    def __init__(self, abi):
        self.function_typedefs = set()  # typedefs of function types
        self.enum_tags = {e["tag"] for e in abi["enums"] if e["tag"]}

    def tokens(self, text):
        return re.findall(r"[A-Za-z_]\w*|\*|\[\d*\]", text)

    def base(self, words):
        words = [w for w in words if w != "const"]
        if words[:1] in (["struct"], ["enum"], ["union"]):
            check(len(words) == 2, f"bad tagged type {words}")
            return words[1]
        key = " ".join(words)
        if key in SCALARS:
            return SCALARS[key]
        if key == "va_list":
            return "VaList<'a>"
        check(len(words) == 1, f"unknown type {key!r}")
        return words[0]

    def rust(self, text, array_as_pointer=False):
        """Return the Rust type for a C type spelled without a name."""
        toks = self.tokens(text)
        arrays = [t for t in toks if t.startswith("[")]
        toks = [t for t in toks if not t.startswith("[")]
        first_star = toks.index("*") if "*" in toks else len(toks)
        base_words, rest = toks[:first_star], toks[first_star:]
        base = self.base(base_words)
        const = "const" in base_words
        ty = base
        stars = 0
        for t in rest:
            if t == "*":
                if base in self.function_typedefs and stars == 0:
                    ty = f"Option<{base}>"
                else:
                    ty = f"*{'const' if const else 'mut'} {ty}"
                stars += 1
                const = False
            else:
                check(t == "const", f"unexpected {t!r} in {text!r}")
                const = True
        for a in arrays:
            n = a[1:-1]
            if array_as_pointer or not n:
                ty = f"*mut {ty}"
            else:
                ty = f"[{ty}; {n}]"
        return ty

    def split_name(self, decl):
        """Split `type name` into (type, name or None)."""
        toks = self.tokens(decl)
        named = [t for t in toks if not t.startswith("[")]
        last = named[-1]
        if (last in C_TYPE_WORDS or last in ("*", "const")
                or len(named) == 1
                or named[-2] in ("struct", "enum", "union")):
            return decl, None
        idx = decl.rindex(last)
        return decl[:idx] + decl[idx + len(last):], last

    def params(self, params, in_proto=False):
        out = []
        for p in params:
            p = p.strip()
            if p == "...":
                out.append("...")
                continue
            if p == "void":
                continue
            ty, _ = self.split_name(p)
            out.append(self.rust(ty, array_as_pointer=True))
        return out

    def returns(self, text):
        text = text.strip()
        return "" if text == "void" else f" -> {self.rust(text)}"


def fn_type(types, params, ret):
    args = types.params(params)
    hrtb = "for<'a> " if any("VaList" in a for a in args) else ""
    return (f"{hrtb}unsafe extern \"C\" fn({', '.join(args)})"
            f"{types.returns(ret)}")


def parse_fn_decl(decl):
    """Split `RET (*name)(params)` or `RET name(params)`."""
    m = re.match(r"^(.*?)\(\s*\*\s*(\w+)\s*\)\s*\((.*)\)$", decl)
    if m:
        return m.group(1), m.group(2), m.group(3), True
    m = re.match(r"^(.*?)\b(\w+)\s*\((.*)\)$", decl)
    check(m is not None, f"unparsed function declaration {decl!r}")
    return m.group(1), m.group(2), m.group(3), False


def split_params(text):
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
            continue
        depth += ch == "("
        depth -= ch == ")"
        cur += ch
    if cur.strip():
        out.append(cur)
    return out


def measurements():
    """
    Return each target's measurement, as `abi.json`'s data: a foreign
    target's layouts, declarations and values in place of the host's.
    """
    host = json.loads(ABI.read_text())["data"]
    check(host["target"] == TARGETS[0][1],
          f"no cfg for probed target {host['target']}")
    out = [host]
    for path, target, _, _ in TARGETS[1:]:
        foreign = json.loads(path.read_text())["data"]
        check(foreign["target"] == target, f"{path.name} is not {target}")
        abi = copy.deepcopy(host)
        abi["target"], abi["compiler"] = target, foreign["compiler"]
        values = {c["name"]: c for c in foreign["constants"]}
        for c in abi["constants"]:
            c["c-type"] = values[c["name"]]["c-type"]
            c["value"] = values[c["name"]]["value"]
        sizes = {(e["typedef"], e["tag"]): e["size"]
                 for e in foreign["enums"]}
        for e in abi["enums"]:
            e["size"] = sizes[e["typedef"], e["tag"]]
        check(sorted(foreign["structs"]) == sorted(abi["structs"]),
              f"{path.name}: struct set")
        abi["structs"] = foreign["structs"]
        check([t["name"] for t in foreign["typedefs"]] ==
              [t["name"] for t in abi["typedefs"]], f"{path.name}: typedefs")
        abi["typedefs"] = foreign["typedefs"]
        out.append(abi)
    return out


def render(abi):
    """
    Return one target's declarations as units, (key, items) with each item
    one Rust item; its prototypes, as units; and its layout assertions.
    """
    types = Types(abi)
    values = {c["name"]: c for c in abi["constants"]}
    units = prelude(abi["target"])
    asserts = []

    def unit(key, *items):
        units.append((key, list(items)))

    # Typedefs of function types (not pointers) are pointers in Rust, so a
    # C pointer to one is an optional Rust function pointer.
    for t in abi["typedefs"]:
        body = t["decl"].removeprefix("typedef ")
        if "(" in body and not body.startswith("enum"):
            _, name, _, is_ptr = parse_fn_decl(body)
            if not is_ptr:
                types.function_typedefs.add(name)

    unit("opaque", "// Opaque handles.")
    for o in abi["opaque-types"]:
        name = o.split()[1]
        unit(o, f"#[repr(C)]\npub struct {name} {{\n    _opaque: [u8; 0],\n}}")

    unit("enums", "// C enums: integer newtypes, one constant per member.")
    for e in sorted(abi["enums"], key=lambda e: e["typedef"] or e["tag"]):
        name = e["typedef"] or e["tag"]
        check(e["size"] == 4, f"enum {name} is not 4 bytes")
        items = [(
            "#[repr(transparent)]\n#[derive(Clone, Copy, PartialEq, Eq, Debug)]\n"
            f"pub struct {name}(pub c_int);")]
        for m in e["members"]:
            c = values.get(m)
            check(c is not None and c["kind"] == "enum",
                  f"no value for enum member {m}")
            items.append(f"pub const {m}: {name} = {name}({c['value']});")
        unit(f"enum {name}", *items)
        asserts.append(f"assert!(size_of::<{name}>() == {e['size']});")

    unit("typedefs", "// Other typedefs.")
    for t in abi["typedefs"]:
        body = t["decl"].removeprefix("typedef ")
        name = t["name"]
        if body.startswith("enum"):
            continue
        if "(" in body:
            ret, fname, params, _ = parse_fn_decl(body)
            check(fname == name, f"typedef name {fname} != {name}")
            ty = fn_type(types, split_params(params), ret)
            if name in types.function_typedefs:
                unit(name, f"pub type {name} = {ty};")
            else:
                unit(name, f"pub type {name} = Option<{ty}>;")
            continue
        m = re.match(r"^(struct|union) (\w+) (\w+)$", body)
        if m:
            check(m.group(3) == name, f"odd typedef {body}")
            items = []
            if m.group(2) != name:
                items.append(f"pub type {name} = {m.group(2)};")
            if (t["size"] is None
                    and f"struct {m.group(2)}" not in abi["opaque-types"]):
                items.append(f"#[repr(C)]\npub struct {m.group(2)} "
                             "{\n    _opaque: [u8; 0],\n}")
            unit(name, *items)
            continue
        ty, tname = types.split_name(body)
        check(tname == name, f"odd typedef {body}")
        unit(name, f"pub type {name} = {types.rust(ty)};")
        if t["size"] is not None and types.rust(ty) != "c_void":
            asserts.append(f"assert!(size_of::<{name}>() == {t['size']});")

    unit("structs", "// Structs, with their anonymous members as named types.")
    for sname in sorted(abi["structs"]):
        s = abi["structs"][sname]
        name = sname.split()[1]
        unit(sname, *struct(types, name, s, asserts))

    unit("macros", "// Macro constants.")
    for c in abi["constants"]:
        if c["kind"] != "macro":
            continue
        if c["value"] is None:
            unit(c["name"])
        elif c["c-type"] == "char *":
            check(re.fullmatch(r'"[^"\\]*"', c["value"]) is not None,
                  f"string constant needing escapes: {c['name']}")
            unit(c["name"], f"pub const {c['name']}: &CStr = c{c['value']};")
        else:
            unit(c["name"], f"pub const {c['name']}: "
                 f"{SCALARS[c['c-type']]} = {c['value']};")

    proto = [(f["name"], [(f"    pub type {f['name']} = "
                           f"{fn_type(types, f['params'], f['returns'])};")])
             for f in sorted(abi["functions"], key=lambda f: f["name"])]
    return units, proto, asserts


def with_cfg(cfg, item):
    """`item` under `#[cfg(cfg)]`, after its leading blank lines."""
    body = item.lstrip("\n")
    indent = body[:len(body) - len(body.lstrip(" "))]
    return f"{item[:len(item) - len(body)]}{indent}#[cfg({cfg})]\n{body}"


def merge(per_target):
    """
    Merge the targets' units into one list of items. An item every target
    renders alike is declared once; one that differs is declared for each
    target, under the cfg of its family. Also returns, by that cfg, the
    items declared for that family alone.
    """
    keys = [k for k, _ in per_target[0]]
    for units in per_target[1:]:
        check([k for k, _ in units] == keys, "targets render different units")
    merged, own = [], {t[3]: [] for t in TARGETS}
    for i in range(len(keys)):
        variants = [units[i][1] for units in per_target]
        if all(v == variants[0] for v in variants):
            merged += variants[0]
            continue
        # Item by item where the shapes agree, so a struct whose layout
        # differs does not take its accessors along.
        if all(len(v) == len(variants[0]) for v in variants):
            rows = [list(row) for row in zip(*variants)]
        else:
            rows = [variants]
        for row in rows:
            if all(item == row[0] for item in row):
                merged.append(row[0])
                continue
            for (_, _, _, cfg), items in zip(TARGETS, row):
                for item in (items if isinstance(items, list) else [items]):
                    merged.append(with_cfg(cfg, item))
                    own[cfg].append(item)
    return merged, own


def scalars_used(text):
    return {n for n in ["CStr", "VaList", *SCALARS.values()]
            if n.startswith(("c_", "C", "V"))
            and re.search(rf"\b{n}\b", text)}


def generate():
    abis = measurements()
    rendered = [render(abi) for abi in abis]
    body, own = merge([units for units, _, _ in rendered])
    proto, own_proto = merge([proto for _, proto, _ in rendered])

    header = (
        genlib.header(HERE, [ABI, ROOT / "gen" / "genlib.py", HERE,
                             *(path for path, _, _, _ in TARGETS[1:])])
        + "//! The C types of libcurl's public headers.\n\n"
        "#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]\n"
        "#![allow(non_snake_case, clippy::upper_case_acronyms)]\n\n")
    proto_mod = ("\n/// The prototype of every public function, to check "
                 "each exported definition\n/// against: "
                 "`const _: proto::curl_free = curl_free;`.\npub mod proto {\n"
                 "    use super::*;\n\n" + "\n".join(proto) + "\n}\n")
    checks = ""
    for abi, (_, _, asserts), (_, _, cfg, _) in zip(abis, rendered, TARGETS):
        checks += (f"\n/// Layouts as {abi.get('compiler', 'gcc')} computed "
                   f"them for {abi['target']}.\n"
                   f"#[cfg({cfg})]\nconst _: () = {{\n    use core::mem::"
                   "{align_of, offset_of, size_of};\n"
                   + "\n".join("    " + a for a in asserts) + "\n};\n")
    rest = "\n".join(body) + "\n" + proto_mod + checks

    # What every target uses is imported once; what only some do, under
    # their cfg, or the others would warn of an unused import.
    shared = "\n".join(i for i in body + proto
                       if not i.lstrip("\n ").startswith("#[cfg("))
    per_cfg = {cfg: scalars_used("\n".join([shared, *own[cfg],
                                            *own_proto[cfg]]))
               for _, _, _, cfg in TARGETS}
    everywhere = set.intersection(*per_cfg.values())

    def use(names):
        names = sorted(names, key=lambda n: (n[0].islower(), n))
        return (f"use core::ffi::{names[0]};\n" if len(names) == 1 else
                "use core::ffi::{" + ", ".join(names) + "};\n")
    imports = use(everywhere) + "".join(
        f"#[cfg({cfg})]\n" + use(names - everywhere)
        for cfg, names in per_cfg.items() if names - everywhere)
    return header + imports + "\n" + rest


def struct(types, name, s, asserts):
    out = []
    fields = s["fields"]
    nested = {f["name"]: f for f in fields if f["decl"] in ("union {...}",
                                                             "struct {...}")}
    top = [f for f in fields if "." not in f["name"]]
    lines = []
    i = 0
    while i < len(top):
        f = top[i]
        if f["name"] in nested:
            kind = "union" if f["decl"].startswith("union") else "struct"
            sub = f"{name}_{f['name']}"
            members = [g for g in fields
                       if g["name"].startswith(f["name"] + ".")]
            sub_lines = []
            for g in members:
                ty, _ = types.split_name(g["decl"])
                sub_lines.append(
                    f"    pub {ident(g['name'].split('.', 1)[1])}: "
                    f"{types.rust(ty)},")
                asserts.append(
                    f"assert!(offset_of!({name}, {ident(f['name'])}) + "
                    f"offset_of!({sub}, "
                    f"{ident(g['name'].split('.', 1)[1])}) == {g['offset']});")
            out.append(f"#[repr(C)]\n#[derive(Clone, Copy)]\npub {kind} {sub} "
                       "{\n" + "\n".join(sub_lines) + "\n}")
            lines.append(f"    pub {ident(f['name'])}: {sub},")
            i += 1
            continue
        if "bit" in f:
            # A run of bitfields shares one storage unit, up to the next
            # field; it is exposed as bytes with accessors.
            run = [f]
            while i + len(run) < len(top) and "bit" in top[i + len(run)]:
                run.append(top[i + len(run)])
            nxt = (top[i + len(run)]["offset"] if i + len(run) < len(top)
                   else s["size"])
            width = nxt - f["offset"]
            store = f"_bits_{f['offset']}"
            lines.append(f"    {store}: [u8; {width}],")
            impl = []
            for b in run:
                check(b["bit-width"] == 1, "only 1-bit bitfields handled")
                byte = b["offset"] - f["offset"] + b["bit"] // 8
                bit = b["bit"] % 8
                impl.append(
                    f"    pub fn {b['name']}(&self) -> bool {{\n"
                    f"        self.{store}[{byte}] & (1 << {bit}) != 0\n    }}\n"
                    f"    pub fn set_{b['name']}(&mut self, on: bool) {{\n"
                    f"        if on {{\n            self.{store}[{byte}] |= "
                    f"1 << {bit};\n        }} else {{\n            "
                    f"self.{store}[{byte}] &= !(1 << {bit});\n        }}\n    }}")
            out.append(f"impl {name} {{\n" + "\n".join(impl) + "\n}")
            asserts.append(f"assert!(offset_of!({name}, {store}) == "
                           f"{f['offset']});")
            i += len(run)
            continue
        ty, _ = types.split_name(f["decl"])
        lines.append(f"    pub {ident(f['name'])}: {types.rust(ty)},")
        asserts.append(f"assert!(offset_of!({name}, {ident(f['name'])}) == "
                       f"{f['offset']});")
        i += 1
    asserts.append(f"assert!(size_of::<{name}>() == {s['size']});")
    asserts.append(f"assert!(align_of::<{name}>() == {s['align']});")
    return [f"#[repr(C)]\n#[derive(Clone, Copy)]\npub struct {name} {{\n"
            + "\n".join(lines) + "\n}", *out]


def main():
    genlib.write(OUT, generate())


if __name__ == "__main__":
    main()
