#!/bin/sh
# usage: memcap.sh <GiB> cmd...   runs cmd in a cgroup-v1 memory group capped at <GiB>, no swap
set -e
gb=$1; shift
cg=/sys/fs/cgroup/memory/cap-$$
mkdir -p $cg
echo $((gb*1024*1024*1024)) > $cg/memory.limit_in_bytes
echo $((gb*1024*1024*1024)) > $cg/memory.memsw.limit_in_bytes 2>/dev/null || true
echo $$ > $cg/cgroup.procs
exec "$@"
