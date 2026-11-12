#!/usr/bin/env bash
# End to end: runs the real PHP app in both modes and checks the verdicts of the Go checker.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -f data/*.sqlite
(cd checker && go build -o vulncheck ./cmd/vulncheck)
VULNSHOP_MODE=vulnerable php -S 127.0.0.1:8200 -t public router.php >/tmp/vulnshop-vuln.log 2>&1 &
P1=$!
VULNSHOP_MODE=secure php -S 127.0.0.1:8201 -t public router.php >/tmp/vulnshop-secure.log 2>&1 &
P2=$!
trap 'kill $P1 $P2 2>/dev/null || true' EXIT
for p in 8200 8201; do
  for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$p/" && break; sleep 0.1; done
done

set +e
out=$(checker/vulncheck -target http://127.0.0.1:8200); code=$?
set -e
echo "$out" | tail -3
[ "$code" -eq 1 ] || { echo "FAIL: vulnerable mode should exit 1, got $code"; exit 1; }
[ "$(echo "$out" | grep -c '\[VULN\]')" -eq 8 ] || { echo "FAIL: expected 8 VULN"; exit 1; }

out=$(checker/vulncheck -target http://127.0.0.1:8201); code=$?
echo "$out" | tail -3
[ "$code" -eq 0 ] || { echo "FAIL: secure mode should exit 0, got $code"; exit 1; }
[ "$(echo "$out" | grep -c '\[PASS\]')" -eq 8 ] || { echo "FAIL: expected 8 PASS"; exit 1; }

# The secure app must still work for a normal user.
jar=$(mktemp)
curl -s -c "$jar" -o /dev/null -d 'username=alice&password=alice123' http://127.0.0.1:8201/login.php
curl -s -b "$jar" http://127.0.0.1:8201/orders.php | grep -q 'Your orders' || { echo "FAIL: secure login broken"; exit 1; }

# Passwords: unsalted MD5 (32 hex chars) in vulnerable mode, bcrypt (60 chars) in secure mode.
len() { php -r '$p = new PDO("sqlite:data/shop-'"$1"'.sqlite"); echo strlen($p->query("select password from users limit 1")->fetchColumn());'; }
[ "$(len vulnerable)" -eq 32 ] || { echo "FAIL: vulnerable mode should store MD5"; exit 1; }
[ "$(len secure)" -eq 60 ] || { echo "FAIL: secure mode should store bcrypt"; exit 1; }
echo "e2e OK"
