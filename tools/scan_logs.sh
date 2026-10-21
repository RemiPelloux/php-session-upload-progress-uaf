#!/usr/bin/env bash
# scan_logs.sh — look for the fingerprint of an exploitation attempt.
#
#   ./scan_logs.sh                       # systemd journals for php-fpm/apache/nginx
#   ./scan_logs.sh /var/log/php8.4-fpm.log /var/log/apache2/error.log
#   ./scan_logs.sh --since "-7 days"
#
# What it looks for, and why:
#   1. "in Unknown on line 0" + memory exhausted
#        -> an OOM during PHP *request startup*, i.e. before any script compiled.
#           For a normal application this basically does not happen; it is the
#           signature of the pre-RINIT serialisation blowing up.
#   2. "zend_mm_heap corrupted"
#        -> the Zend allocator's consistency check tripping, followed by SIGABRT
#           (exit 134 / signal 6) on that worker.
#   3. The two together on the same worker, seconds apart
#        -> the full arm-then-fire sequence.
set -u

SINCE="-24 hours"
FILES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --since) SINCE="$2"; shift 2 ;;
    *) FILES+=("$1"); shift ;;
  esac
done

hr() { printf '%s\n' "------------------------------------------------------------"; }

hr
echo "1) pre-RINIT OOM  (request startup, no script compiled)"
hr
if [ ${#FILES[@]} -gt 0 ]; then
  grep -Hn -E 'memory size of [0-9]+ bytes exhausted.*in Unknown on line 0' "${FILES[@]}" 2>/dev/null | tail -40 \
    || echo "  none"
else
  journalctl --since "$SINCE" 2>/dev/null \
    | grep -E 'memory size of [0-9]+ bytes exhausted.*in Unknown on line 0' | tail -40 \
    || echo "  none (or journalctl not available for this user)"
fi

hr
echo "2) allocator abort"
hr
if [ ${#FILES[@]} -gt 0 ]; then
  grep -Hn -E 'zend_mm_heap corrupted|zend_mm_heap corrupted.*Aborted' "${FILES[@]}" 2>/dev/null | tail -40 \
    || echo "  none"
else
  journalctl --since "$SINCE" 2>/dev/null | grep -E 'zend_mm_heap corrupted' | tail -40 || echo "  none"
fi

hr
echo "3) worker aborts (exit 134 / signal 6) on php units"
hr
journalctl --since "$SINCE" 2>/dev/null \
  | grep -E '(php|fpm|apache)[^ ]*: .*(signal 6|exit code 134|core dumped)' | tail -20 \
  || echo "  none (or no systemd units matched)"

hr
cat <<'EOF'
Reading the result
  - A single "in Unknown on line 0" OOM is a probe. Finding one is worth a look.
  - "zend_mm_heap corrupted" without an accompanying Unknown-line-0 OOM is
    usually something else (extension bug, xdebug teardown, bad opcache); do not
    conclude this bug from that line alone.
  - Both lines, same worker, seconds apart -> treat it as this sequence.

Containment
  1. session.upload_progress.enabled = Off   (see REMEDIATION.md)
  2. recycle every PHP worker afterwards: the corrupted worker is already gone,
     but restart pools so you know what you are running.
  3. preserve logs before rotation if this might be an incident.
EOF
