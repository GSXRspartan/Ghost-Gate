#!/usr/bin/env bash
# Report what the build is currently spending memory on.
#
# The host has ~5 GB total and Windows needs its own share. When this reports WSL holding most of it,
# the next step is not "wait longer" -- it is a host restart, which costs more than the build.
set -uo pipefail

echo "=== WSL memory ==="
free -m | sed -n '1,3p'

echo
echo "=== swap ==="
free -m | sed -n 3p

echo
echo "=== heaviest processes in WSL ==="
ps -eo pcpu,rss,args --sort=-rss | head -5 | cut -c1-140

echo
echo "=== last build line ==="
tail -2 /root/e2e.log 2>/dev/null || echo "(no log)"