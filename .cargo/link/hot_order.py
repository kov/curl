#!/usr/bin/env python3
"""
Lay the hot functions of a release libcurl and curl out first in `.text`.

`.cargo/link/cc` hands a link here when its arguments carry
`--curl-hot-order=<list>`, which the build scripts of curl-sys-abi and
curl-tool add to the release links of the library and the tool (and which
cargo hands the tool's unit tests too: those link unordered). The
list names functions by their demangled paths without crate hashes, which
stay the same across toolchains, features and profiles where the mangled
names do not; this resolves them against the symbols of the link's own
objects, and passes the linker the result:

- GNU ld 2.43 or later: `--section-ordering-file`, each function's own
  section (rustc gives every function one, `.text.<mangled name>`);
- LLD (rustc's own on x86_64 Linux, or the system's): `--symbol-ordering-file`.

Any other linker (mold, gold, an older GNU ld) links unordered. That, and a
list of which too few entries resolve, is said on standard error, which
rustc reports as a `linker stderr` warning.

`python3 hot_order.py check <list> <binary>` asserts the order took effect
in a linked binary; `inventory/measure/order.py` writes the lists.
"""

import os
import pathlib
import re
import shutil
import subprocess
import sys

MARKER = "--curl-hot-order="
# Below this share of the list resolving, the list is stale: regenerate it
# with inventory/measure/order.py.
MIN_RESOLVED = 0.8
# The crate disambiguator c++filt prints after a crate's name.
DISAMBIGUATOR = re.compile(r"(?<=[A-Za-z0-9_])\[[0-9a-f]+\]")
# A local symbol LLVM renamed when it promoted it.
SUFFIX = re.compile(r"\.llvm\.[0-9]+$")


def keys(names):
    """
    The list keys of mangled symbol `names`, in their order: the demangled
    path with crate disambiguators and LLVM's suffixes dropped. A name
    that is not Rust's is its own key.
    """
    names = [SUFFIX.sub("", n) for n in names]
    if not names:
        return []
    out = subprocess.run(["c++filt"], input="\n".join(names) + "\n",
                         check=True, capture_output=True,
                         text=True).stdout.split("\n")[:len(names)]
    assert len(out) == len(names), "c++filt returned fewer lines than names"
    return [DISAMBIGUATOR.sub("", d) if n.startswith("_R") else n
            for n, d in zip(names, out)]


def read_list(path):
    """The keys a list names, in order, without comments."""
    return [line for line in pathlib.Path(path).read_text().splitlines()
            if line and not line.startswith("#")]


FUNCTION = re.compile(r"^[0-9a-f]+ (.{7}) (\S+)\t[0-9a-f]+ (?:\.hidden )?(\S+)$")


def functions(objects):
    """
    (mangled name, section) of every function of `objects` that has a
    section of its own, as `objdump -t` lists them.
    """
    found = []
    for obj in objects:
        table = subprocess.run(["objdump", "-t", obj], check=True,
                               capture_output=True, text=True).stdout
        for line in table.splitlines():
            m = FUNCTION.match(line)
            if m and "F" in m.group(1) and m.group(2).startswith(".text."):
                found.append((m.group(3), m.group(2)))
    return found


def linker(cc_args):
    """
    ("gnu", (major, minor)), ("lld", None) or (name, None) for any other:
    the linker the link's compiler driver runs, asked for its version with
    the arguments that choose it.
    """
    choose = []
    args = iter(cc_args)
    for a in args:
        if a.startswith(("-fuse-ld=", "--ld-path=")) or \
                (a.startswith("-B") and len(a) > 2):
            choose.append(a)
        elif a == "-B":
            choose += [a, next(args)]
    r = subprocess.run(["cc", *choose, "-Wl,--version"], check=False,
                       capture_output=True, text=True)
    first = (r.stdout.splitlines() or ["unknown linker"])[0]
    if first.startswith("GNU ld"):
        m = re.search(r"(\d+)\.(\d+)", first.split(")")[-1])
        return "gnu", (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    if first.startswith("LLD"):
        return "lld", None
    return first.split()[0] if first.split() else first, None


def warn(output, text):
    print(f"curl hot-function order, {os.path.basename(output)}: {text}",
          file=sys.stderr)


def expand(argv):
    """The arguments with response files (`@file`) read in."""
    out = []
    for a in argv:
        if a.startswith("@") and os.path.isfile(a[1:]):
            out += [line.strip('"') for line in
                    pathlib.Path(a[1:]).read_text().splitlines() if line]
        else:
            out.append(a)
    return out


def test_harness():
    """
    Whether rustc, which runs the linker, is building a test harness: cargo
    gives a binary's test the link arguments of the binary itself.
    """
    rustc = pathlib.Path(f"/proc/{os.getppid()}/cmdline").read_bytes()
    return b"--test" in rustc.split(b"\0")


def link(argv):
    args = expand(argv)
    lists = [a[len(MARKER):] for a in args if a.startswith(MARKER)]
    args = [a for a in args if not a.startswith(MARKER)]
    if not lists or test_harness():
        os.execvp("cc", ["cc", *argv] if not lists else ["cc", *args])
    assert len(lists) == 1, f"several lists: {lists}"
    output = args[args.index("-o") + 1]
    missing = [t for t in ("objdump", "c++filt") if not shutil.which(t)]
    if missing:
        warn(output, f"no {' or '.join(missing)} to read the objects with: "
             "linked unordered")
        os.execvp("cc", ["cc", *args])
    kind, version = linker(args)
    if kind == "gnu" and version < (2, 43):
        warn(output, f"GNU ld {version[0]}.{version[1]} has no "
             "--section-ordering-file (2.43 and later have): linked unordered")
        os.execvp("cc", ["cc", *args])
    if kind not in ("gnu", "lld"):
        warn(output, f"{kind} takes no ordering file: linked unordered")
        os.execvp("cc", ["cc", *args])
    wanted = read_list(lists[0])
    objects = [a for a in args if a.endswith(".o") and os.path.isfile(a)]
    found = functions(objects)
    by_key = {}
    for (name, section), key in zip(found, keys([n for n, _ in found])):
        by_key.setdefault(key, []).append((name, section))
    # What could be ordered, for inventory/measure/order.py: the functions
    # it finds hot that are in this list are the ones a list may name.
    pathlib.Path(f"{output}.hot-keys").write_text(
        "".join(f"{key}\n" for key in sorted(by_key)))
    ordered = [hit for key in wanted for hit in by_key.get(key, [])]
    resolved = sum(1 for key in wanted if key in by_key)
    if resolved < MIN_RESOLVED * len(wanted):
        warn(output, f"{resolved} of the {len(wanted)} functions in "
             f"{lists[0]} found: the list is stale, regenerate it with "
             "inventory/measure/order.py")
    path = f"{output}.hot-order"
    if kind == "gnu":
        body = "".join(f"  *({section})\n" for _, section in ordered)
        pathlib.Path(path).write_text(f".text : {{\n{body}}}\n")
        extra = [f"-Wl,--section-ordering-file={path}"]
    else:
        pathlib.Path(path).write_text("".join(f"{n}\n" for n, _ in ordered))
        extra = [f"-Wl,--symbol-ordering-file={path}",
                 "-Wl,--no-warn-symbol-ordering"]
    os.execvp("cc", ["cc", *args, *extra])


def text_symbols(binary):
    """(address, mangled name) of `binary`'s functions in `.text`, by
    address."""
    sections = subprocess.run(["readelf", "-SW", binary], check=True,
                              capture_output=True, text=True).stdout
    m = re.search(r"\] \.text\s+PROGBITS\s+([0-9a-f]+) [0-9a-f]+ ([0-9a-f]+)",
                  sections)
    assert m, f"{binary} has no .text"
    start, size = int(m.group(1), 16), int(m.group(2), 16)
    out = []
    table = subprocess.run(["nm", "--defined-only", binary], check=True,
                           capture_output=True, text=True).stdout
    for line in table.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in "tT":
            addr = int(parts[0], 16)
            if start <= addr < start + size:
                out.append((addr, parts[2]))
    return sorted(set(out))


def check(list_path, binary):
    """
    Fail unless `binary`'s `.text` starts with the functions `list_path`
    names that it has, in the list's order. The positive control: at least
    MIN_RESOLVED of the list is in the binary at all, so an empty or
    foreign list cannot pass for an order.
    """
    wanted = read_list(list_path)
    rank = {key: i for i, key in enumerate(wanted)}
    symbols = text_symbols(binary)
    named = keys([n for _, n in symbols])
    present = {k for k in named if k in rank}
    assert len(present) >= MIN_RESOLVED * len(wanted), \
        f"{binary}: {len(present)} of {len(wanted)} listed functions present"
    # Symbols of one function sharing its address (aliases) count once;
    # the listed ones must come first, then none.
    head = named[:sum(1 for k in named if k in rank)]
    stray = [k for k in head if k not in rank]
    assert not stray, (f"{binary}: .text starts with unlisted functions, "
                       f"first {stray[0]!r}: not ordered")
    ranks = [rank[k] for k in head]
    disorder = sum(1 for a, b in zip(ranks, ranks[1:]) if b < a)
    assert disorder == 0, f"{binary}: {disorder} listed functions out of order"
    return len(present), len(wanted)


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "link":
        link(sys.argv[2:])
    elif len(sys.argv) == 4 and sys.argv[1] == "check":
        present, total = check(sys.argv[2], sys.argv[3])
        print(f"{sys.argv[3]}: ordered, {present} of {total} listed")
    else:
        sys.exit("usage: hot_order.py link <cc args...> | "
                 "check <list> <binary>")


if __name__ == "__main__":
    main()
