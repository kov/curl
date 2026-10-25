# Lists sabotage entries whose `old` text is not in their file exactly once (run from the
# repository root): faster to read than `sabotage_entries_are_current`'s failure.
import pathlib, sys
for f in sorted(pathlib.Path('sabotage/entries').glob('*.txt')):
    lines = f.read_text().split('\n')
    i = 0
    while i < len(lines):
        if lines[i].startswith('=== '):
            name = lines[i][4:]; file = None; i += 1
            while i < len(lines) and lines[i] != '--- old':
                if lines[i].startswith('file: '): file = lines[i][6:]
                i += 1
            i += 1; old = []
            while i < len(lines) and lines[i] != '--- new':
                old.append(lines[i]); i += 1
            text = '\n'.join(old)
            src = pathlib.Path(file).read_text()
            if src.count(text) != 1:
                print(f"{f.name}: {name} [{file}] count={src.count(text)}")
        else:
            i += 1
