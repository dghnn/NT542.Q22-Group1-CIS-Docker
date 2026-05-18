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

echo "===== CIS Docker Audit Script ====="
echo

# 1.1.1 Separate partition for containers
if mountpoint -q /var/lib/docker && grep -q " /var/lib/docker " /proc/mounts; then
  pass "1.1.1 /var/lib/docker is mounted separately"
else
  fail "1.1.1 /var/lib/docker is NOT mounted separately"
fi

# 1.1.2 Docker group
DOCKER_GROUP=$(getent group docker)
if [ -n "$DOCKER_GROUP" ]; then
  echo "Docker group: $DOCKER_GROUP"
  warn "1.1.2 Review users in docker group manually"
else
  pass "1.1.2 Docker group does not exist or has no users"
fi

# 1.2.1 Host hardening checks
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

ROOT_LOGIN=$(sudo grep -Ei "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null)
if echo "$ROOT_LOGIN" | grep -Eqi "no|prohibit-password"; then
  pass "1.2.1 SSH root login is restricted"
else
  fail "1.2.1 SSH root login is not clearly restricted"
fi

# 1.2.2 Docker version
if command -v docker >/dev/null 2>&1; then
  docker version --format 'Docker Client: {{.Client.Version}} | Server: {{.Server.Version}}'
  warn "1.2.2 Compare Docker version with official latest version manually"
else
  fail "1.2.2 Docker is not installed"
fi

# Storage driver checks: 2.6 and 2.7
DRIVER=$(docker info --format '{{ .Driver }}' 2>/dev/null)

if [ "$DRIVER" != "aufs" ] && [ -n "$DRIVER" ]; then
  pass "2.6 Storage driver is not aufs: $DRIVER"
else
  fail "2.6 Storage driver is aufs or unknown"
fi

if [ "$DRIVER" != "devicemapper" ] && [ -n "$DRIVER" ]; then
  pass "2.7 Storage driver is not devicemapper: $DRIVER"
else
  fail "2.7 Storage driver is devicemapper or unknown"
fi

# 2.11 cgroup-parent
if [ -f /etc/docker/daemon.json ]; then
  if grep -q "cgroup-parent" /etc/docker/daemon.json; then
    fail "2.11 cgroup-parent is configured"
  else
    pass "2.11 cgroup-parent is not configured"
  fi
else
  pass "2.11 daemon.json not found, cgroup-parent not configured"
fi

# 2.12 dm.basesize
if [ -f /etc/docker/daemon.json ]; then
  if grep -q "dm.basesize" /etc/docker/daemon.json; then
    fail "2.12 dm.basesize is configured"
  else
    pass "2.12 dm.basesize is not configured"
  fi
else
  pass "2.12 daemon.json not found, dm.basesize not configured"
fi

# Function check owner
check_owner() {
  FILE=$1
  EXPECT=$2
  CIS=$3

  if [ -e "$FILE" ]; then
    OWNER=$(stat -c '%U:%G' "$FILE")
    if [ "$OWNER" = "$EXPECT" ]; then
      pass "$CIS Owner is $OWNER"
    else
      fail "$CIS Owner is $OWNER, expected $EXPECT"
    fi
  else
    warn "$CIS $FILE not found"
  fi
}

# Function check permission
check_perm() {
  FILE=$1
  MAX=$2
  CIS=$3

  if [ -e "$FILE" ]; then
    PERM=$(stat -c '%a' "$FILE")
    if [ "$PERM" -le "$MAX" ]; then
      pass "$CIS Permission is $PERM"
    else
      fail "$CIS Permission is $PERM, expected <= $MAX"
    fi
  else
    warn "$CIS $FILE not found"
  fi
}

# 3.1 - 3.4 systemd files
DOCKER_SERVICE=$(systemctl show -p FragmentPath docker.service 2>/dev/null | cut -d= -f2)
DOCKER_SOCKET=$(systemctl show -p FragmentPath docker.socket 2>/dev/null | cut -d= -f2)

check_owner "$DOCKER_SERVICE" "root:root" "3.1 docker.service"
check_perm "$DOCKER_SERVICE" 644 "3.2 docker.service"

check_owner "$DOCKER_SOCKET" "root:root" "3.3 docker.socket"
check_perm "$DOCKER_SOCKET" 644 "3.4 docker.socket"

# 3.5 - 3.6 /etc/docker
check_owner "/etc/docker" "root:root" "3.5 /etc/docker"
check_perm "/etc/docker" 755 "3.6 /etc/docker"

# 3.15 - 3.16 docker.sock
check_owner "/var/run/docker.sock" "root:docker" "3.15 docker.sock"
check_perm "/var/run/docker.sock" 660 "3.16 docker.sock"

# 3.23 - 3.24 containerd.sock
check_owner "/run/containerd/containerd.sock" "root:root" "3.23 containerd.sock"
check_perm "/run/containerd/containerd.sock" 660 "3.24 containerd.sock"

echo
echo "===== SUMMARY ====="
echo "PASS: $PASS"
echo "FAIL: $FAIL"
echo "WARN: $WARN"
