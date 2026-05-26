#!/bin/bash

PASS=0
FAIL=0
WARN=0

pass() {
  echo "[PASS] $1"
  PASS=$((PASS+1))
}

fail() {
  echo "[FAIL] $1"
  FAIL=$((FAIL+1))
}

warn() {
  echo "[WARN] $1"
  WARN=$((WARN+1))
}

echo "===== CIS Docker Audit Script - Key 5 Controls ====="
echo

# 1.1.1 Separate partition for containers
if mountpoint -q /var/lib/docker && grep -q " /var/lib/docker " /proc/mounts; then
  pass "1.1.1 /var/lib/docker is mounted separately"
else
  fail "1.1.1 /var/lib/docker is NOT mounted separately"
fi

# 1.2.1 Host hardening checks - Firewall
if command -v ufw >/dev/null 2>&1; then
  UFW_STATUS=$(sudo ufw status | head -n 1)
  echo "UFW: $UFW_STATUS"

  if echo "$UFW_STATUS" | grep -qi "active"; then
    pass "1.2.1 Firewall is active"
  else
    fail "1.2.1 Firewall is inactive"
  fi
else
  warn "1.2.1 UFW not installed, check firewall manually"
fi

# 1.2.1 Host hardening checks - SSH Root Login
ROOT_LOGIN=$(sudo grep -Ei "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null)

if echo "$ROOT_LOGIN" | grep -Eqi "no|prohibit-password"; then
  pass "1.2.1 SSH root login is restricted"
else
  fail "1.2.1 SSH root login is not clearly restricted"
fi

# 2.7 Do not use devicemapper storage driver
DRIVER=$(docker info --format '{{ .Driver }}' 2>/dev/null)

if [ "$DRIVER" != "devicemapper" ] && [ -n "$DRIVER" ]; then
  pass "2.7 Storage driver is not devicemapper: $DRIVER"
else
  fail "2.7 Storage driver is devicemapper or unknown"
fi

# 3.15 Docker socket ownership
if [ -e /var/run/docker.sock ]; then
  OWNER=$(stat -c '%U:%G' /var/run/docker.sock)

  if [ "$OWNER" = "root:docker" ]; then
    pass "3.15 docker.sock owner is root:docker"
  else
    fail "3.15 docker.sock owner is $OWNER, expected root:docker"
  fi
else
  warn "3.15 /var/run/docker.sock not found"
fi

# 3.16 Docker socket permissions
if [ -e /var/run/docker.sock ]; then
  PERM=$(stat -c '%a' /var/run/docker.sock)

  if [ "$PERM" -le 660 ]; then
    pass "3.16 docker.sock permission is $PERM"
  else
    fail "3.16 docker.sock permission is $PERM, expected <= 660"
  fi
else
  warn "3.16 /var/run/docker.sock not found"
fi

echo
echo "===== SUMMARY ====="
echo "PASS: $PASS"
echo "FAIL: $FAIL"
echo "WARN: $WARN"