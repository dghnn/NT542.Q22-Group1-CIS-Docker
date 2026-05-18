#!/bin/bash

PASS=0
FAIL=0
WARN=0
INFO=0

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

info() {
  echo "[INFO] $1"
  INFO=$((INFO+1))
}

echo "===== CIS Docker Image & Supply Chain Security Audit ====="
echo

if ! command -v docker >/dev/null 2>&1; then
  fail "Docker command not found"
  echo
  echo "===== SUMMARY ====="
  echo "PASS: $PASS"
  echo "FAIL: $FAIL"
  echo "WARN: $WARN"
  echo "INFO: $INFO"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  fail "Docker daemon is not running or current user cannot access Docker"
  echo
  echo "===== SUMMARY ====="
  echo "PASS: $PASS"
  echo "FAIL: $FAIL"
  echo "WARN: $WARN"
  echo "INFO: $INFO"
  exit 1
fi

IMAGES=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep -v '<none>' || true)
RUNNING_CONTAINERS=$(docker ps -q || true)
ALL_CONTAINERS=$(docker ps -aq || true)

if [ -z "$IMAGES" ]; then
  warn "No Docker images found. CIS 4.x image checks are skipped"
else
  info "Found Docker images:"
  echo "$IMAGES"
  echo
fi

if [ -z "$ALL_CONTAINERS" ]; then
  warn "No Docker containers found. Container runtime checks are skipped"
else
  info "Found Docker containers:"
  docker ps -a --format 'table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}'
  echo
fi

# 4.1 USER non-root
if [ -n "$IMAGES" ]; then
  for image in $IMAGES; do
    USER_CFG=$(docker inspect --format='{{.Config.User}}' "$image" 2>/dev/null)

    if [ -n "$USER_CFG" ] && [ "$USER_CFG" != "root" ] && [ "$USER_CFG" != "0" ]; then
      pass "4.1 $image has non-root USER: $USER_CFG"
    else
      fail "4.1 $image has no non-root USER configured"
    fi
  done
else
  warn "4.1 skipped because no image exists"
fi

# 4.2 Trusted base image
if [ -n "$IMAGES" ]; then
  for image in $IMAGES; do
    if echo "$image" | grep -Eq '^(ubuntu|debian|alpine|nginx|httpd|mysql|postgres|redis|python|node|php|golang|openjdk|busybox):'; then
      warn "4.2 $image appears to be official/common image, verify trust manually"
    else
      warn "4.2 $image must be manually verified as trusted base image"
    fi
  done
else
  warn "4.2 skipped because no image exists"
fi

# 4.3 Unnecessary packages
BAD_PKGS="gcc g++ make git curl wget telnet netcat nc openssh-client vim nano unzip"
if [ -n "$RUNNING_CONTAINERS" ]; then
  for cid in $RUNNING_CONTAINERS; do
    FOUND=0

    for pkg in $BAD_PKGS; do
      if docker exec "$cid" sh -c "command -v $pkg >/dev/null 2>&1" 2>/dev/null; then
        echo "[FOUND] Container $cid has package/tool: $pkg"
        FOUND=1
      fi
    done

    if [ "$FOUND" -eq 0 ]; then
      pass "4.3 Container $cid has no common unnecessary tools detected"
    else
      fail "4.3 Container $cid contains unnecessary/dev tools"
    fi
  done
else
  warn "4.3 skipped because no running container exists"
fi

# 4.4 Security updates
if [ -n "$RUNNING_CONTAINERS" ]; then
  for cid in $RUNNING_CONTAINERS; do
    if docker exec "$cid" sh -c "command -v apt-get >/dev/null 2>&1" 2>/dev/null; then
      OUTDATED=$(docker exec "$cid" sh -c \
        "apt-get update >/dev/null 2>&1 && apt-get upgrade -s 2>/dev/null | grep '^Inst' | wc -l" \
        2>/dev/null || echo 0)
      OUTDATED=${OUTDATED:-0}
      if [ "$OUTDATED" -eq 0 ]; then
        pass "4.4 Container $cid has no pending apt package updates"
      else
        fail "4.4 Container $cid has $OUTDATED pending package updates"
      fi
    elif docker exec "$cid" sh -c "command -v apk >/dev/null 2>&1" 2>/dev/null; then
      warn "4.4 Container $cid uses apk. Review package updates manually"
    elif docker exec "$cid" sh -c "command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1" 2>/dev/null; then
      warn "4.4 Container $cid uses yum/dnf. Review package updates manually"
    else
      warn "4.4 Container $cid package manager not detected"
    fi
  done
else
  warn "4.4 skipped because no running container exists"
fi

# 4.5 Docker Content Trust
if [ "$DOCKER_CONTENT_TRUST" = "1" ]; then
  pass "4.5 Docker Content Trust is enabled"
else
  fail "4.5 Docker Content Trust is not enabled"
fi

# 4.6 HEALTHCHECK
if [ -n "$IMAGES" ]; then
  for image in $IMAGES; do
    HC=$(docker inspect --format='{{json .Config.Healthcheck}}' "$image" 2>/dev/null)

    if [ "$HC" != "null" ] && [ -n "$HC" ]; then
      pass "4.6 $image has HEALTHCHECK"
    else
      fail "4.6 $image has no HEALTHCHECK"
    fi
  done
else
  warn "4.6 skipped because no image exists"
fi

# 4.7 apt-get update alone
if [ -n "$IMAGES" ]; then
  for image in $IMAGES; do
    BAD=$(docker history --no-trunc "$image" 2>/dev/null | grep -Ei 'apt-get update|apt update' | grep -Ev '&&|;|install' | wc -l)

    if [ "$BAD" -eq 0 ]; then
      pass "4.7 $image has no standalone apt-get update layer"
    else
      fail "4.7 $image has standalone apt-get update layer"
    fi
  done
else
  warn "4.7 skipped because no image exists"
fi

# 4.8 setuid/setgid
if [ -n "$ALL_CONTAINERS" ]; then
  for cid in $ALL_CONTAINERS; do
    SUID_COUNT=$(docker export "$cid" 2>/dev/null | tar -tv 2>/dev/null | grep -E '^[-rwx].*(s|S)' | wc -l)

    if [ "$SUID_COUNT" -eq 0 ]; then
      pass "4.8 Container $cid has no SUID/SGID files detected"
    else
      fail "4.8 Container $cid has $SUID_COUNT SUID/SGID files"
    fi
  done
else
  warn "4.8 skipped because no container exists"
fi

# 4.9 COPY instead of ADD
if [ -n "$IMAGES" ]; then
  for image in $IMAGES; do
    ADD_COUNT=$(docker history --no-trunc "$image" 2>/dev/null | grep -w 'ADD' | wc -l)

    if [ "$ADD_COUNT" -eq 0 ]; then
      pass "4.9 $image does not use ADD"
    else
      fail "4.9 $image uses ADD instruction"
    fi
  done
else
  warn "4.9 skipped because no image exists"
fi

# 4.10 No secrets in Dockerfile/history
SECRET_PATTERNS='PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|ACCESS_KEY|PRIVATE_KEY|AWS_SECRET|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD'

if [ -n "$IMAGES" ]; then
  for image in $IMAGES; do
    SECRET_FOUND=$(docker history --no-trunc "$image" 2>/dev/null | grep -Ei "$SECRET_PATTERNS" | wc -l)

    if [ "$SECRET_FOUND" -eq 0 ]; then
      pass "4.10 $image has no obvious secrets in image history"
    else
      fail "4.10 $image may contain secrets in image history"
    fi
  done
else
  warn "4.10 skipped because no image exists"
fi

# 4.11 Verified packages
if [ -n "$IMAGES" ]; then
  for image in $IMAGES; do
    VERIFY_FOUND=$(docker history --no-trunc "$image" 2>/dev/null | grep -Ei 'gpg|sha256sum|apt-key|signed-by|cosign' | wc -l)

    if [ "$VERIFY_FOUND" -gt 0 ]; then
      warn "4.11 $image shows package/signature verification evidence, review manually"
    else
      warn "4.11 $image has no obvious package verification evidence"
    fi
  done
else
  warn "4.11 skipped because no image exists"
fi

# 4.12 Signed artifacts validation
if [ -n "$IMAGES" ]; then
  for image in $IMAGES; do
    ARTIFACT_VERIFY=$(docker history --no-trunc "$image" 2>/dev/null | grep -Ei 'gpg --verify|sha256sum -c|cosign verify' | wc -l)

    if [ "$ARTIFACT_VERIFY" -gt 0 ]; then
      warn "4.12 $image shows signed artifact validation evidence, review manually"
    else
      warn "4.12 $image has no obvious signed artifact validation evidence"
    fi
  done
else
  warn "4.12 skipped because no image exists"
fi

# 2.10 User namespace
if docker info --format '{{json .SecurityOptions}}' 2>/dev/null | grep -q 'userns'; then
  pass "2.10 User namespace support is enabled"
else
  fail "2.10 User namespace support is not enabled"
fi

# 2.13 Authorization plugin
AUTH_PLUGIN=$(docker info --format '{{json .Plugins.Authorization}}' 2>/dev/null)

if [ "$AUTH_PLUGIN" = "[]" ] || [ "$AUTH_PLUGIN" = "null" ] || [ -z "$AUTH_PLUGIN" ]; then
  warn "2.13 No Docker authorization plugin configured, verify policy manually"
else
  pass "2.13 Authorization plugin is configured: $AUTH_PLUGIN"
fi

# 2.15 no-new-privileges
if [ -n "$ALL_CONTAINERS" ]; then
  for cid in $ALL_CONTAINERS; do
    NNP=$(docker inspect --format='{{json .HostConfig.SecurityOpt}}' "$cid" 2>/dev/null | grep -c 'no-new-privileges')

    if [ "$NNP" -gt 0 ]; then
      pass "2.15 Container $cid has no-new-privileges enabled"
    else
      fail "2.15 Container $cid does not have no-new-privileges"
    fi
  done
else
  warn "2.15 skipped because no container exists"
fi

# 2.18 Seccomp
if [ -n "$ALL_CONTAINERS" ]; then
  for cid in $ALL_CONTAINERS; do
    SECCOMP=$(docker inspect --format='{{json .HostConfig.SecurityOpt}}' "$cid" 2>/dev/null)

    if echo "$SECCOMP" | grep -q 'seccomp=unconfined'; then
      fail "2.18 Container $cid has seccomp disabled/unconfined"
    else
      pass "2.18 Container $cid does not disable seccomp"
    fi
  done
else
  warn "2.18 skipped because no container exists"
fi

# 2.19 Experimental features
EXPERIMENTAL=$(docker version --format '{{.Server.Experimental}}' 2>/dev/null)

if [ "$EXPERIMENTAL" = "false" ]; then
  pass "2.19 Docker experimental features are disabled"
elif [ "$EXPERIMENTAL" = "true" ]; then
  fail "2.19 Docker experimental features are enabled"
else
  warn "2.19 Cannot determine Docker experimental feature status"
fi

# 3.17 - 3.22 file owner and permission
check_file_owner_perm() {
  CIS_OWNER=$1
  CIS_PERM=$2
  FILE=$3

  if [ ! -e "$FILE" ]; then
    pass "$CIS_OWNER/$CIS_PERM $FILE does not exist, Not Applicable"
    return
  fi

  OWNER=$(stat -c '%U:%G' "$FILE")
  PERM=$(stat -c '%a' "$FILE")

  if [ "$OWNER" = "root:root" ]; then
    pass "$CIS_OWNER $FILE owner is root:root"
  else
    fail "$CIS_OWNER $FILE owner is $OWNER, expected root:root"
  fi

  if [ "$PERM" -le 644 ]; then
    pass "$CIS_PERM $FILE permission is $PERM"
  else
    fail "$CIS_PERM $FILE permission is $PERM, expected <= 644"
  fi
}

check_file_owner_perm "3.17" "3.18" "/etc/docker/daemon.json"
check_file_owner_perm "3.19" "3.20" "/etc/default/docker"
check_file_owner_perm "3.22" "3.21" "/etc/sysconfig/docker"

echo
echo "===== SUMMARY ====="
echo "PASS: $PASS"
echo "FAIL: $FAIL"
echo "WARN: $WARN"
echo "INFO: $INFO"
