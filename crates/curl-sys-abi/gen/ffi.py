#!/usr/bin/env python3
"""
Generate src/ffi.rs, the C types of libcurl's public headers, from abi.json.

inventory/abi.json holds what gcc computed from include/curl: constant
values, struct layouts, typedefs and prototypes. This turns them into Rust
declarations for the C ABI shim:

  - C enums become `#[repr(transparent)]` integer newtypes with one constant
    per member, never Rust enums: a value from C may be any integer, and an
    out-of-range Rust enum is undefined behaviour before it can be checked;
  - every struct gets compile-time assertions of its size, alignment and
    field offsets, as gcc measured them, on the target abi.json was probed on;
  - every public function gets a function-pointer type in `proto`, so an
    exported definition can be checked against its prototype at build time.

The output records a hash of its inputs; a test in the crate recomputes it,
so a stale ffi.rs fails `cargo test`. `--check` exits non-zero instead of
writing when ffi.rs is out of date.
"""

import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve()
CRATE = HERE.parents[1]
ROOT = HERE.parents[3]
ABI = ROOT / "inventory" / "abi.json"
OUT = CRATE / "src" / "ffi.rs"

# The probed target's layout assertions apply only to it.
TARGETS = {"aarch64-redhat-linux":
           'all(target_os = "linux", target_arch = "aarch64")'}

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
    "double": "f64", "float": "f32", "void": "c_void",
}
C_TYPE_WORDS = {"char", "short", "int", "long", "unsigned", "signed",
                "double", "float", "void"}

PRELUDE = """\
// System types the headers use. Their layouts are checked below with the
// rest, from the sizes gcc reported for the curl structs that embed them.
pub type time_t = c_long;
pub type socklen_t = c_uint;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr {
    pub sa_family: c_ushort,
    pub sa_data: [c_char; 14],
}

/// Only ever behind a pointer.
#[repr(C)]
pub struct FILE {
    _opaque: [u8; 0],
}

/// Only ever behind a pointer.
#[repr(C)]
pub struct fd_set {
    _opaque: [u8; 0],
}
"""


def fnv1a(data):
    """FNV-1a, 64 bits: enough to detect a stale file, not a security hash."""
    h = 0xcbf29ce484222325
    for b in data:
        h = ((h ^ b) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h


def inputs_hash():
    # The C commit stamp changes with every C commit; the content may not.
    abi = b"".join(line for line in ABI.read_bytes().splitlines(keepends=True)
                   if not line.startswith(b' "c-commit": '))
    return fnv1a(abi + HERE.read_bytes())


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


def check(cond, msg):
    if not cond:
        sys.exit(f"ffi.py: {msg}")


def generate():
    abi = json.loads(ABI.read_text())["data"]
    types = Types(abi)
    target = TARGETS.get(abi["target"])
    check(target is not None, f"no cfg for probed target {abi['target']}")
    values = {c["name"]: c for c in abi["constants"]}
    out = []
    asserts = []

    # Typedefs of function types (not pointers) are pointers in Rust, so a
    # C pointer to one is an optional Rust function pointer.
    for t in abi["typedefs"]:
        body = t["decl"].removeprefix("typedef ")
        if "(" in body and not body.startswith("enum"):
            _, name, _, is_ptr = parse_fn_decl(body)
            if not is_ptr:
                types.function_typedefs.add(name)

    out.append("// Opaque handles.")
    for o in abi["opaque-types"]:
        name = o.split()[1]
        out.append(f"#[repr(C)]\npub struct {name} {{\n    _opaque: [u8; 0],\n}}")

    out.append("// C enums: integer newtypes, one constant per member.")
    for e in sorted(abi["enums"], key=lambda e: e["typedef"] or e["tag"]):
        name = e["typedef"] or e["tag"]
        check(e["size"] == 4, f"enum {name} is not 4 bytes")
        out.append(
            "#[repr(transparent)]\n#[derive(Clone, Copy, PartialEq, Eq, Debug)]\n"
            f"pub struct {name}(pub c_int);")
        for m in e["members"]:
            c = values.get(m)
            check(c is not None and c["kind"] == "enum",
                  f"no value for enum member {m}")
            out.append(f"pub const {m}: {name} = {name}({c['value']});")
        asserts.append(f"assert!(size_of::<{name}>() == {e['size']});")

    out.append("// Other typedefs.")
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
                out.append(f"pub type {name} = {ty};")
            else:
                out.append(f"pub type {name} = Option<{ty}>;")
            continue
        m = re.match(r"^(struct|union) (\w+) (\w+)$", body)
        if m:
            check(m.group(3) == name, f"odd typedef {body}")
            if m.group(2) != name:
                out.append(f"pub type {name} = {m.group(2)};")
            if (t["size"] is None
                    and f"struct {m.group(2)}" not in abi["opaque-types"]):
                out.append(f"#[repr(C)]\npub struct {m.group(2)} "
                           "{\n    _opaque: [u8; 0],\n}")
            continue
        ty, tname = types.split_name(body)
        check(tname == name, f"odd typedef {body}")
        out.append(f"pub type {name} = {types.rust(ty)};")
        if t["size"] is not None and types.rust(ty) != "c_void":
            asserts.append(f"assert!(size_of::<{name}>() == {t['size']});")

    out.append("// Structs, with their anonymous members as named types.")
    for sname in sorted(abi["structs"]):
        s = abi["structs"][sname]
        name = sname.split()[1]
        out += struct(types, name, s, asserts)

    out.append("// Macro constants.")
    for c in abi["constants"]:
        if c["kind"] != "macro" or c["value"] is None:
            continue
        if c["c-type"] == "char *":
            check(re.fullmatch(r'"[^"\\]*"', c["value"]) is not None,
                  f"string constant needing escapes: {c['name']}")
            out.append(f"pub const {c['name']}: &CStr = c{c['value']};")
        else:
            out.append(f"pub const {c['name']}: {SCALARS[c['c-type']]} = "
                       f"{c['value']};")

    proto = [f"    pub type {f['name']} = "
             f"{fn_type(types, f['params'], f['returns'])};"
             for f in sorted(abi["functions"], key=lambda f: f["name"])]

    header = (
        "// Generated by crates/curl-sys-abi/gen/ffi.py from "
        "inventory/abi.json. Do not edit;\n// regenerate.\n"
        f"// inputs-hash: {inputs_hash():016x}\n\n"
        "//! The C types of libcurl's public headers.\n\n"
        "#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]\n"
        "#![allow(non_snake_case, clippy::upper_case_acronyms)]\n\n"
        "use core::ffi::{{{}}};\n\n")
    body = "\n".join([PRELUDE] + out)
    proto_mod = ("\n/// The prototype of every public function, to check "
                 "each exported definition\n/// against: "
                 "`const _: proto::curl_free = curl_free;`.\npub mod proto {\n"
                 "    use super::*;\n\n" + "\n".join(proto) + "\n}\n")
    checks = (f"\n/// Layouts as gcc computed them for {abi['target']}.\n"
              f"#[cfg({target})]\nconst _: () = {{\n    use core::mem::"
              "{align_of, offset_of, size_of};\n"
              + "\n".join("    " + a for a in asserts) + "\n};\n")
    rest = body + "\n" + proto_mod + checks
    used = sorted({n for n in ["CStr", "VaList", *SCALARS.values()]
                   if n.startswith(("c_", "C", "V"))
                   and re.search(rf"\b{n}\b", rest)},
                  key=lambda n: (n[0].islower(), n))
    return header.format(", ".join(used)) + rest


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
    text = generate()
    if "--check" in sys.argv[1:]:
        check(OUT.exists() and OUT.read_text() == text,
              f"{OUT.relative_to(ROOT)} is stale; run {HERE.relative_to(ROOT)}")
        return
    OUT.write_text(text)


if __name__ == "__main__":
    main()
