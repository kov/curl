#!/bin/sh
# cargo-mutants over one crate, per .cargo/mutants.toml's recipe, under a memory cap, from a
# clean worktree of the commit under test (cargo-mutants copies it; a dirty tree mutates junk).
# usage: run_mutants.sh <worktree> <diff-base> <name> <cargo-mutants args...>
#   run_mutants.sh build/mutants-tree 2b6a502 core -p curl-core --test-package curl-core \
#     --features curl-core/test-util,curl-core/debug-hooks -- -- --skip the_system_s_ipv6_probe_is_the_system_s
#   run_mutants.sh build/mutants-tree 2b6a502 abi -p curl-sys-abi --features curl-sys-abi/debug-hooks
#   run_mutants.sh build/mutants-tree 2b6a502 openssl -p curl-openssl --test-package curl-openssl -- -- a_verified_get resum
#   run_mutants.sh build/mutants-tree 2b6a502 tool -p curl-tool --features curl-tool/debug-hooks
# Output: <worktree>/../mutants-<name>/mutants.out/{caught,missed,timeout,unviable}.txt, log in
# <worktree>/../mutants-<name>.log. --iterate skips mutants already caught, so a run killed by
# a container restart resumes. Check the log every 10 minutes (CLAUDE.md).
D=$(cd "$(dirname "$0")" && pwd)
tree=$1 base=$2 name=$3; shift 3
cd "$tree" || exit 1
git diff "$base"..HEAD > ../mutants.diff
export TMPDIR=$(pwd)/../tmp; mkdir -p "$TMPDIR"
"$D/testenv.sh" "$D/memcap.sh" 8 cargo mutants --iterate -o "../mutants-$name" --in-diff ../mutants.diff "$@" \
  > "../mutants-$name.log" 2>&1
echo "$name-exit=$?" >> "../mutants-$name.log"
