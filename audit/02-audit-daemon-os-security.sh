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

check_audit_rule() {
  CIS_ID=$1
  TARGET=$2
  MODE=$3

  if [ "$MODE" = "optional" ] && [ ! -e "$TARGET" ]; then
    pass "$CIS_ID $TARGET does not exist, not applicable"
    return
  fi

  if auditctl -l 2>/dev/null | grep -q "$TARGET"; then
    pass "$CIS_ID audit rule exists for $TARGET"
  else
    fail "$CIS_ID audit rule missing for $TARGET"
  fi
}

check_owner() {
  CIS_ID=$1
  FILE=$2
  EXPECT=$3

  if [ ! -e "$FILE" ]; then
    pass "$CIS_ID $FILE does not exist, not applicable"
    return
  fi

  OWNER=$(stat -c "%U:%G" "$FILE")
  if [ "$OWNER" = "$EXPECT" ]; then
    pass "$CIS_ID owner is $OWNER"
  else
    fail "$CIS_ID owner is $OWNER, expected $EXPECT"
  fi
}

check_perm_max() {
  CIS_ID=$1
  FILE=$2
  MAX=$3

  if [ ! -e "$FILE" ]; then
    pass "$CIS_ID $FILE does not exist, not applicable"
    return
  fi

  PERM=$(stat -c "%a" "$FILE")
  if [ "$PERM" -le "$MAX" ]; then
    pass "$CIS_ID permission is $PERM"
  else
    fail "$CIS_ID permission is $PERM, expected <= $MAX"
  fi
}

check_perm_exact() {
  CIS_ID=$1
  FILE=$2
  EXPECT=$3

  if [ ! -e "$FILE" ]; then
    pass "$CIS_ID $FILE does not exist, not applicable"
    return
  fi

  PERM=$(stat -c "%a" "$FILE")
  if [ "$PERM" = "$EXPECT" ]; then
    pass "$CIS_ID permission is $PERM"
  else
    fail "$CIS_ID permission is $PERM, expected $EXPECT"
  fi
}

echo "===== CIS Docker Benchmark Audit Script - Part 2 ====="
echo

# Check auditctl
if ! command -v auditctl >/dev/null 2>&1; then
  warn "auditctl not found. auditd is not installed"
fi

# 1.1.3 - 1.1.18 Audit rules
check_audit_rule "1.1.3" "/usr/bin/dockerd" "required"
check_audit_rule "1.1.4" "/run/containerd" "required"
check_audit_rule "1.1.5" "/var/lib/docker" "required"
check_audit_rule "1.1.6" "/etc/docker" "required"

DOCKER_SERVICE=$(systemctl show -p FragmentPath docker.service 2>/dev/null | cut -d= -f2)
[ -n "$DOCKER_SERVICE" ] && check_audit_rule "1.1.7" "$DOCKER_SERVICE" "required" || warn "1.1.7 docker.service not found"

check_audit_rule "1.1.8" "/run/containerd/containerd.sock" "optional"
check_audit_rule "1.1.9" "/var/run/docker.sock" "optional"
check_audit_rule "1.1.10" "/etc/default/docker" "optional"
check_audit_rule "1.1.11" "/etc/docker/daemon.json" "optional"
check_audit_rule "1.1.12" "/etc/containerd/config.toml" "optional"
check_audit_rule "1.1.13" "/etc/sysconfig/docker" "optional"
check_audit_rule "1.1.14" "/usr/bin/containerd" "optional"
check_audit_rule "1.1.15" "/usr/bin/containerd-shim" "optional"
check_audit_rule "1.1.16" "/usr/bin/containerd-shim-runc-v1" "optional"
check_audit_rule "1.1.17" "/usr/bin/containerd-shim-runc-v2" "optional"
check_audit_rule "1.1.18" "/usr/bin/runc" "optional"

# 2.1 Docker rootless
DOCKER_USER=$(ps -eo user,comm | awk '$2=="dockerd"{print $1}' | head -n 1)

if [ -z "$DOCKER_USER" ]; then
  warn "2.1 dockerd process not found"
elif [ "$DOCKER_USER" = "root" ]; then
  warn "2.1 Docker daemon is running as root, not rootless"
else
  pass "2.1 Docker daemon is running as non-root user: $DOCKER_USER"
fi

# 2.3 Log level
if [ -f /etc/docker/daemon.json ]; then
  if grep -q '"log-level"[[:space:]]*:[[:space:]]*"debug"' /etc/docker/daemon.json; then
    fail "2.3 Docker log-level is debug"
  else
    pass "2.3 Docker log-level is not debug, default/info is acceptable"
  fi
else
  pass "2.3 daemon.json not found, Docker default log-level info is acceptable"
fi

# 2.8 TLS authentication
if ss -lntp 2>/dev/null | grep -q "dockerd.*:2375"; then
  fail "2.8 Docker daemon is exposed on TCP 2375 without TLS"
elif ss -lntp 2>/dev/null | grep -q "dockerd.*:2376"; then
  if [ -f /etc/docker/daemon.json ] &&
     grep -q '"tlsverify"[[:space:]]*:[[:space:]]*true' /etc/docker/daemon.json &&
     grep -q '"tlscacert"' /etc/docker/daemon.json &&
     grep -q '"tlscert"' /etc/docker/daemon.json &&
     grep -q '"tlskey"' /etc/docker/daemon.json; then
    pass "2.8 Docker TCP TLS authentication is configured"
  else
    fail "2.8 Docker TCP is exposed but TLS config is incomplete"
  fi
else
  pass "2.8 Docker daemon is not exposed over TCP"
fi

# 2.14 Centralized logging
LOG_DRIVER=$(docker info --format '{{.LoggingDriver}}' 2>/dev/null)

if [ -z "$LOG_DRIVER" ]; then
  warn "2.14 Cannot detect Docker logging driver"
elif [ "$LOG_DRIVER" = "json-file" ]; then
  fail "2.14 Logging driver is json-file, no centralized remote logging"
else
  pass "2.14 Logging driver is $LOG_DRIVER"
fi

# 3.7 - 3.8 Registry certificate files
if [ -d /etc/docker/certs.d ]; then
  BAD_OWNER=$(find /etc/docker/certs.d -type f ! -user root -o ! -group root 2>/dev/null)
  if [ -z "$BAD_OWNER" ]; then
    pass "3.7 Registry certificate files are owned by root:root"
  else
    fail "3.7 Some registry certificate files are not root:root"
    echo "$BAD_OWNER"
  fi

  BAD_PERM=$(find /etc/docker/certs.d -type f -perm /0222 2>/dev/null)
  if [ -z "$BAD_PERM" ]; then
    pass "3.8 Registry certificate files are 444 or more restrictive"
  else
    fail "3.8 Some registry certificate files are writable"
    echo "$BAD_PERM"
  fi
else
  pass "3.7/3.8 /etc/docker/certs.d does not exist, not applicable"
fi

# 3.9 - 3.14 TLS cert/key checks from daemon.json
if [ -f /etc/docker/daemon.json ]; then
  CACERT=$(grep -oP '"tlscacert"[[:space:]]*:[[:space:]]*"\K[^"]+' /etc/docker/daemon.json)
  CERT=$(grep -oP '"tlscert"[[:space:]]*:[[:space:]]*"\K[^"]+' /etc/docker/daemon.json)
  KEY=$(grep -oP '"tlskey"[[:space:]]*:[[:space:]]*"\K[^"]+' /etc/docker/daemon.json)

  [ -n "$CACERT" ] && check_owner "3.9 TLS CA cert" "$CACERT" "root:root" || pass "3.9 TLS CA cert not configured, not applicable"
  [ -n "$CACERT" ] && check_perm_max "3.10 TLS CA cert" "$CACERT" 444 || true

  [ -n "$CERT" ] && check_owner "3.11 Docker server cert" "$CERT" "root:root" || pass "3.11 Docker server cert not configured, not applicable"
  [ -n "$CERT" ] && check_perm_max "3.12 Docker server cert" "$CERT" 444 || true

  [ -n "$KEY" ] && check_owner "3.13 Docker server key" "$KEY" "root:root" || pass "3.13 Docker server key not configured, not applicable"
  [ -n "$KEY" ] && check_perm_exact "3.14 Docker server key" "$KEY" 400 || true
else
  pass "3.9 - 3.14 daemon.json not found, TLS files not configured, not applicable"
fi

echo
echo "===== SUMMARY ====="
echo "PASS: $PASS"
echo "FAIL: $FAIL"
echo "WARN: $WARN"
