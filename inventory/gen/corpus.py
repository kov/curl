"""
Rank what real command lines ask of the curl tool.

Reads inventory/corpus_lines.json, the invocations of the tool that
inventory/measure/corpus_run.py --collect found in the sources of the
distribution's packages that use it, each with its package, file and line,
and inventory/cli.json, C's option table. Splits each invocation as a shell
splits it, reads its options against the table, and writes
inventory/corpus.json and inventory/corpus.md: which options, spellings and
pairs of options are used, and how often.

The shell splitting here (`lex`, `invocations`, `words`) is also what the
collector cuts the invocations out of their files with, and what
corpus_run.py --diff runs them from.
"""

import collections
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import common
from common import check, md_table

LINES = common.INVENTORY / "corpus_lines.json"

# Control operators, longest first; a redirection operator may follow an
# fd number glued to it (`2>&1`).
CONTROL = ["||", "&&", "|&", ";;", "|", ";", "&", "(", ")"]
REDIRECT = ["&>>", "<<<", "<<-", "<<", ">>", ">|", "<>", ">&", "<&", "&>",
            ">", "<"]
# Words that keep the next word in command position: keywords, and the
# wrappers that run the command they are given.
KEYWORDS = {"then", "do", "else", "elif", "if", "while", "until", "!", "{",
            "time", "exec", "command", "nohup", "builtin"}
WRAPPERS = {"sudo", "env", "timeout", "xargs", "nice", "stdbuf", "retry",
            "eatmydata", "fakeroot", "proxychains", "torsocks", "unbuffer"}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")


class LexError(Exception):
    pass


def _skip_dollar(text, i):
    """
    Return the end of the expansion starting with `$` at `i`: `$(...)`,
    `$((...))`, `${...}`, `$'...'`, `$name` or `$1`, `$@` and the like.
    """
    n = len(text)
    if i + 1 >= n:
        return i + 1
    c = text[i + 1]
    if c == "(":
        return _skip_group(text, i + 2, ")") + 1
    if c == "{":
        j = i + 2
        depth = 1
        while j < n and depth:
            if text[j] == "\\":
                j += 2
                continue
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
            j += 1
        if depth:
            raise LexError("unterminated ${")
        return j
    if c == "'":
        return _skip_ansi(text, i + 2)
    if c == '"':
        return _skip_double(text, i + 2)
    if c.isalpha() or c == "_":
        j = i + 1
        while j < n and (text[j].isalnum() or text[j] == "_"):
            j += 1
        return j
    if c.isdigit() or c in "@*#?-$!":
        return i + 2
    return i + 1


def _skip_ansi(text, j):
    """After `$'`: the end of the ANSI-C quoted string."""
    n = len(text)
    while j < n:
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == "'":
            return j + 1
        j += 1
    raise LexError("unterminated $'")


def _skip_double(text, j):
    """After an opening `"`: the end of the double-quoted string."""
    n = len(text)
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
        elif c == '"':
            return j + 1
        elif c == "$":
            j = _skip_dollar(text, j)
        elif c == "`":
            j = _skip_backquote(text, j + 1)
        else:
            j += 1
    raise LexError('unterminated "')


def _skip_backquote(text, j):
    """After an opening backquote: the end of the command it quotes."""
    n = len(text)
    while j < n:
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == "`":
            return j + 1
        j += 1
    raise LexError("unterminated `")


def _skip_group(text, j, close):
    """From inside `$(`: the index of its closing parenthesis."""
    n = len(text)
    depth = 1
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "'":
            k = text.find("'", j + 1)
            if k < 0:
                raise LexError("unterminated '")
            j = k + 1
            continue
        if c == '"':
            j = _skip_double(text, j + 1)
            continue
        if c == "`":
            j = _skip_backquote(text, j + 1)
            continue
        if c == "$":
            j = _skip_dollar(text, j)
            continue
        if c == "(":
            depth += 1
        elif c == close:
            depth -= 1
            if not depth:
                return j
        j += 1
    raise LexError("unterminated $(")


def lex(text):
    """
    Split one logical line into tokens as a shell does: a list of
    (kind, raw, start, end), kind "word", "op" or "redir". Quotes and
    expansions stay in a word's raw text; a comment ends the line.
    """
    tokens = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c == "#":
            break
        op = next((o for o in CONTROL if text.startswith(o, i)), None)
        redir = next((o for o in REDIRECT if text.startswith(o, i)), None)
        if redir:
            tokens.append(("redir", redir, i, i + len(redir)))
            i += len(redir)
            continue
        if op:
            tokens.append(("op", op, i, i + len(op)))
            i += len(op)
            continue
        start = i
        while i < n:
            c = text[i]
            if c in " \t\r\n":
                break
            if c == "\\":
                i += 2
                continue
            if c == "'":
                k = text.find("'", i + 1)
                if k < 0:
                    raise LexError("unterminated '")
                i = k + 1
                continue
            if c == '"':
                i = _skip_double(text, i + 1)
                continue
            if c == "`":
                i = _skip_backquote(text, i + 1)
                continue
            if c == "$":
                i = _skip_dollar(text, i)
                continue
            if any(text.startswith(o, i) for o in CONTROL):
                break
            if any(text.startswith(o, i) for o in REDIRECT):
                # `2>file`: the fd number belongs to the redirection.
                if text[start:i].isdigit():
                    tokens.append(("redir", text[start:i], start, i))
                    start = None
                break
            i += 1
        if start is not None and i > start:
            tokens.append(("word", text[start:i], start, min(i, n)))
        i = min(i, n)
    # Glue an fd number to its operator: `2`, `>&` makes one redirection.
    out = []
    for t in tokens:
        if out and out[-1][0] == "redir" and out[-1][1].isdigit() and t[0] == "redir":
            prev = out.pop()
            t = ("redir", prev[1] + t[1], prev[2], t[3])
        out.append(t)
    return out


def word_parts(raw):
    """
    Return a word's value as a shell builds it, as (text, expanded, quoted)
    parts: literal text with quotes removed, and each expansion kept as
    its raw text, marked quoted when it cannot split into several words.
    """
    parts = []
    i, n = 0, len(raw)

    def lit(s, quoted=True):
        parts.append((s, False, quoted))

    while i < n:
        c = raw[i]
        if c == "\\":
            if i + 1 < n:
                lit(raw[i + 1])
            i += 2
        elif c == "'":
            k = raw.index("'", i + 1)
            lit(raw[i + 1:k])
            i = k + 1
        elif c == '"':
            end = _skip_double(raw, i + 1) - 1
            j = i + 1
            while j < end:
                d = raw[j]
                if d == "\\" and j + 1 < end and raw[j + 1] in '"\\$`\n':
                    lit(raw[j + 1])
                    j += 2
                elif d == "$" and j + 1 < end:
                    k = _skip_dollar(raw, j)
                    if k == j + 1:
                        lit("$")
                    else:
                        parts.append((raw[j:k], True, True))
                    j = k
                elif d == "`":
                    k = _skip_backquote(raw, j + 1)
                    parts.append((raw[j:k], True, True))
                    j = k
                else:
                    lit(d)
                    j += 1
            i = end + 1
        elif c == "$" and raw.startswith("$'", i):
            k = _skip_ansi(raw, i + 2)
            body = raw[i + 2:k - 1]
            lit(body.encode("latin-1", "backslashreplace")
                .decode("unicode_escape", "replace"))
            i = k
        elif c == "$":
            k = _skip_dollar(raw, i)
            if k == i + 1:
                lit("$", False)
            else:
                parts.append((raw[i:k], True, False))
            i = k
        elif c == "`":
            k = _skip_backquote(raw, i + 1)
            parts.append((raw[i:k], True, False))
            i = k
        else:
            lit(c, False)
            i += 1
    return parts


def word_value(raw, placeholder=None):
    """
    Return the word's text with its quotes removed: each expansion kept as its
    raw text, or replaced by `placeholder` when one is given.
    """
    return "".join(placeholder if (expanded and placeholder is not None) else text
                   for text, expanded, _ in word_parts(raw))


def splits(raw):
    """
    Whether the word holds an unquoted expansion, which may become
    several words, or none."""
    return any(expanded and not quoted for _, expanded, quoted in word_parts(raw))


def _is_curl(raw):
    value = word_value(raw)
    return value == "curl" or value.endswith("/curl")


def invocations(text):
    """
    Return the curl invocations in one logical line: (start, end) of the text
    from the command word to the last word of its simple command, for each
    `curl` (or `/path/to/curl`) in command position, those inside command
    substitutions included.
    """
    found = []
    try:
        tokens = lex(text)
    except LexError:
        return found
    at_command = True
    wrapper = None
    i = 0
    while i < len(tokens):
        kind, raw, start, end = tokens[i]
        if kind == "op":
            at_command = raw != ")"
            wrapper = None
            i += 1
            continue
        if kind == "redir":
            i += 2
            continue
        # Command substitutions in any word hold commands of their own.
        for sub_start, sub_end in _substitutions(raw):
            for s, e in invocations(raw[sub_start:sub_end]):
                found.append((start + sub_start + s, start + sub_start + e))
        if at_command:
            value = word_value(raw)
            if _is_curl(raw):
                last = end
                j = i + 1
                while j < len(tokens) and tokens[j][0] != "op":
                    if tokens[j][0] == "redir":
                        j += 2
                        continue
                    if tokens[j][0] == "word":
                        last = tokens[j][3]
                        for sub_start, sub_end in _substitutions(tokens[j][1]):
                            for s, e in invocations(tokens[j][1][sub_start:sub_end]):
                                found.append((tokens[j][2] + sub_start + s,
                                              tokens[j][2] + sub_start + e))
                    j += 1
                found.append((start, last))
                at_command = False
                i = j
                continue
            if value in KEYWORDS or ASSIGNMENT.match(value):
                i += 1
                continue
            if value in WRAPPERS:
                wrapper = value
                i += 1
                continue
            if wrapper and (value.startswith("-") or value.replace(".", "").isdigit()
                            or (wrapper == "sudo" and tokens[i - 1][1] in ("-u", "-g"))):
                i += 1
                continue
            at_command = False
        i += 1
    return sorted(set(found))


def _substitutions(raw):
    """
    Return the (start, end) of the inside of each `$(...)` and backquote in a
    word."""
    subs = []
    i, n = 0, len(raw)
    while i < n:
        c = raw[i]
        if c == "\\":
            i += 2
        elif c == "'":
            k = raw.find("'", i + 1)
            i = n if k < 0 else k + 1
        elif c == "$" and raw.startswith("$((", i):
            i = _skip_dollar(raw, i)
        elif c == "$" and raw.startswith("$(", i):
            k = _skip_dollar(raw, i)
            subs.append((i + 2, k - 1))
            i = k
        elif c == "`":
            k = _skip_backquote(raw, i + 1)
            subs.append((i + 1, k - 1))
            i = k
        else:
            i += 1
    return subs


def words(text):
    """
    Return the words of the invocation `text` (as `invocations` cut it), the
    command word first: redirections and their targets left out, each
    word's raw text kept.
    """
    out = []
    tokens = lex(text)
    i = 0
    while i < len(tokens):
        kind, raw = tokens[i][0], tokens[i][1]
        if kind == "op":
            break
        if kind == "redir":
            i += 2
            continue
        out.append(raw)
        i += 1
    return out


class Table:
    """C's option table, by long name and by short letter."""

    def __init__(self, cli):
        entries = cli["data"]["option_table"]["entries"]
        self.long = {e["long"]: e for e in entries}
        self.short = {e["short"]: e for e in entries if e["short"]}

    def takes_arg(self, entry):
        return entry["type"] not in ("ARG_NONE", "ARG_BOOL")

    def find_long(self, name):
        """
        Return the entry `--name` means and how it is spelled: exact, `no-`,
        or a unique abbreviation, as C's `getparameter` reads it."""
        if name in self.long:
            return self.long[name], "long"
        if name.startswith("no-") and name[3:] in self.long \
                and "ARG_NO" in self.long[name[3:]]["flags"]:
            return self.long[name[3:]], "no"
        base = name[3:] if name.startswith("no-") else name
        hits = [n for n in self.long if n.startswith(base)]
        if len(hits) == 1:
            return self.long[hits[0]], "abbrev"
        return None, "unknown"


def read_options(argv, table):
    """
    Return the options of an invocation's words after the command word, as C's
    tool reads them: a list of (long name or the word, spelling), and
    whether a word that may split stands where an option could.
    """
    used = []
    opaque = False
    i = 0
    while i < len(argv):
        raw = argv[i]
        word = word_value(raw)
        i += 1
        if splits(raw) and word_value(raw, "") == "":
            opaque = True
            continue
        if word == "--":
            break
        if not word.startswith("-") or word == "-":
            continue
        if word.startswith("--"):
            entry, spelling = table.find_long(word[2:])
            if entry is None:
                used.append((word, "unknown"))
                continue
            used.append((entry["long"], spelling))
            if table.takes_arg(entry) and spelling != "no":
                i += 1
            continue
        # A cluster of short options: one taking an argument takes the
        # rest of the word, or the next word.
        letters = word[1:]
        j = 0
        while j < len(letters):
            entry = table.short.get(letters[j])
            if entry is None:
                used.append((f"-{letters[j]}", "unknown"))
                j += 1
                continue
            used.append((entry["long"], "short"))
            if table.takes_arg(entry):
                if j + 1 == len(letters):
                    i += 1
                break
            j += 1
    return used, opaque


def self_check(table):
    """Known inputs, split and read as a shell and C's tool do."""
    line = 'x=$(curl -sSL "$URL" | tee a) && sudo -E curl -o f --retry 3 http://h/ 2>&1'
    got = [line[s:e] for s, e in invocations(line)]
    check(got == ['curl -sSL "$URL"', 'curl -o f --retry 3 http://h/'], f"invocations: {got}")
    check(words('curl -H "A: b" >out \'x y\'') == ["curl", "-H", '"A: b"', "'x y'"], "words")
    check(word_value('"a $B"c\\ d') == "a $Bc d", "word value")
    check(splits("$OPTS") and not splits('"$OPTS"'), "splits")
    used, opaque = read_options(["-sSLo", "f", "--no-progress-meter", "--verb", "$X"], table)
    check(used == [("silent", "short"), ("show-error", "short"), ("location", "short"),
                   ("output", "short"), ("progress-meter", "no"), ("verbose", "abbrev")],
          f"options: {used}")
    check(opaque, "a lone expansion is opaque")
    check(invocations("echo curl -x") == [], "curl as an argument")
    check(invocations("/usr/bin/curl -s u") == [(0, 18)], "a path to curl")
    check([line[s:e] for line in ["`curl -s u`"] for s, e in invocations(line)]
          == ["curl -s u"], "backquotes")


def summarize(lines, table):
    by_option = collections.Counter()
    occurrences = collections.Counter()
    spellings = collections.defaultdict(collections.Counter)
    unknown = collections.Counter()
    pairs = collections.Counter()
    kinds = collections.Counter()
    packages = collections.defaultdict(set)
    opaque_lines = 0
    unparsed = 0
    for rec in lines:
        kinds[rec["kind"]] += 1
        try:
            argv = words(rec["text"])[1:]
        except (LexError, ValueError):
            unparsed += 1
            continue
        used, opaque = read_options(argv, table)
        opaque_lines += opaque
        names = set()
        for name, spelling in used:
            if spelling == "unknown":
                unknown[name] += 1
                continue
            occurrences[name] += 1
            spellings[name][spelling] += 1
            names.add(name)
            packages[name].add(rec["package"])
        for name in names:
            by_option[name] += 1
        for a in sorted(names):
            for b in sorted(names):
                if a < b:
                    pairs[(a, b)] += 1
    ranked = [{"option": name, "lines": by_option[name], "uses": occurrences[name],
               "packages": len(packages[name]),
               "spellings": dict(sorted(spellings[name].items()))}
              for name in sorted(by_option, key=lambda n: (-by_option[n], n))]
    unused = sorted(set(table.long) - set(by_option))
    return {
        "lines": len(lines),
        "unparsed": unparsed,
        "opaque_lines": opaque_lines,
        "by_kind": dict(sorted(kinds.items())),
        "options": ranked,
        "unknown": [{"word": w, "uses": c}
                    for w, c in sorted(unknown.items(), key=lambda x: (-x[1], x[0]))],
        "pairs": [{"pair": list(p), "lines": c}
                  for p, c in sorted(pairs.items(), key=lambda x: (-x[1], x[0]))[:100]],
        "unused": unused,
    }


def markdown(meta, s):
    taken = collections.Counter(p["why"] for p in meta["packages"])
    found = collections.Counter(p["why"] for p in meta["packages"] if p["invocations"])
    out = ["# Corpus of real command lines\n",
           (f"{s['lines']} invocations of the curl tool, from {sum(found.values())} of the "
            f"{len(meta['packages'])} source packages of {meta['distribution']} read "
            f"(collected {meta['collected']} by `inventory/measure/corpus_run.py --collect`). "
            f"{s['unparsed']} could not be split; {s['opaque_lines']} have a word that may "
            "split into options (`$OPTS`), whose options are not all counted.\n"),
           "## The packages read\n",
           md_table(["why", "read", "with an invocation"],
                    [[w, taken[w], found[w]] for w in sorted(taken)]),
           "## By kind of source\n",
           md_table(["kind", "invocations"], list(s["by_kind"].items())),
           "## Options, by the invocations using them\n",
           md_table(["option", "invocations", "uses", "packages", "spellings"],
                    [[f"--{o['option']}", o["lines"], o["uses"], o["packages"],
                      ", ".join(f"{k} {v}" for k, v in o["spellings"].items())]
                     for o in s["options"]]),
           "## Words read as options C's table does not know\n",
           md_table(["word", "uses"], [[u["word"], u["uses"]] for u in s["unknown"][:50]]),
           "## Pairs of options used together\n",
           md_table(["pair", "invocations"],
                    [[" ".join(f"--{x}" for x in p["pair"]), p["lines"]]
                     for p in s["pairs"][:40]]),
           "## Options no invocation uses\n",
           ", ".join(f"`--{o}`" for o in s["unused"]) + "\n"]
    return "\n".join(out)


def main():
    cli = json.loads((common.INVENTORY / "cli.json").read_text())
    table = Table(cli)
    self_check(table)
    if not LINES.exists():
        sys.exit("corpus.py: no inventory/corpus_lines.json; "
                 "run inventory/measure/corpus_run.py --collect")
    corpus = json.loads(LINES.read_text())
    s = summarize(corpus["lines"], table)
    # Positive control: a corpus of curl invocations uses -s and -L.
    names = {o["option"] for o in s["options"][:30]}
    check({"silent", "location"} <= names, f"the usual options are ranked: {sorted(names)}")
    meta = {k: corpus[k] for k in ("distribution", "collected", "packages")}
    data = {"distribution": meta["distribution"], "collected": meta["collected"],
            "packages": len(meta["packages"]), **s}
    common.write("corpus", data, markdown(meta, s),
                 ["src/tool_getparam.c"], generated_by="inventory/gen/corpus.py")


if __name__ == "__main__":
    main()
