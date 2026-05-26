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

#lấy danh sách images, containers
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

# Kiểm tra UID thực tế của các container đang chạy
if [ -n "$RUNNING_CONTAINERS" ]; then
  for container in $RUNNING_CONTAINERS; do
    # Lấy UID của tiến trình số 1 bên trong container
    EFFECTIVE_UID=$(docker exec "$container" cat /proc/1/status | grep '^Uid:' | awk '{print $3}' 2>/dev/null)
    
    if [ "$EFFECTIVE_UID" != "0" ] && [ -n "$EFFECTIVE_UID" ]; then
      pass "4.1 Container $container is running with non-root UID: $EFFECTIVE_UID"
    else
      fail "4.1 Container $container is running as root (UID 0)"
    fi
  done
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


# 4.8 Ensure setuid and setgid permissions are removed (Level 2 - Manual)
if [ -n "$ALL_CONTAINERS" ]; then
  for cid in $ALL_CONTAINERS; do
    # Sử dụng chính xác Regex từ nguồn tài liệu CIS: [1-6, 10-12] thay vì [1-9]
    SUID_FILES=$(docker export "$cid" 2>/dev/null | tar -tv 2>/dev/null | grep -E '^[-rwx].*(s|S).*\s[1-6, 10-12]' | awk '{print $NF}')
    SUID_COUNT=$(echo "$SUID_FILES" | grep -v '^$' | wc -l)

    if [ "$SUID_COUNT" -eq 0 ]; then
      pass "4.8 Container $cid has no SUID/SGID files"
    else
      # CIS yêu cầu "Review the list" để đảm bảo các file đó thực sự cần thiết
      fail "4.8 Container $cid has $SUID_COUNT SUID/SGID files."
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


# 2.10 Enable user namespace support (Level 2)
# Kiểm tra userns trong Security Options theo Audit Procedure [1]
if docker info --format '{{ .SecurityOptions }}' 2>/dev/null | grep -q 'userns'; then
  pass "2.10 User namespace support is enabled"
else
  fail "2.10 User namespace support is not enabled"
fi

# 2.13 Ensure that authorization for Docker client commands is enabled (Level 2)
# Kiểm tra đồng thời cả tham số dòng lệnh và file config daemon.json [3, 4]
AUTH_FLAG=$(ps -ef | grep dockerd | grep -v grep | grep -c "authorization-plugin" || echo 0)
AUTH_JSON=$(grep -E "authorization-plugin|authorization-plugins" /etc/docker/daemon.json 2>/dev/null | grep -c ":" || echo 0)

if [ "$AUTH_FLAG" -gt 0 ] || [ "$AUTH_JSON" -gt 0 ]; then
  pass "2.13 Authorization plugin is configured"
else
  # Rationale: Mô hình mặc định 'all or nothing' rất nguy hiểm [5]
  fail "2.13 No Docker authorization plugin configured in daemon settings"
fi

# 2.15 Ensure containers are restricted from acquiring new privileges (Level 1)
# Kiểm tra trong tệp daemon.json hoặc tham số dòng lệnh của dockerd [6]
# Sử dụng -e để xử lý chuỗi bắt đầu bằng dấu gạch ngang và đảm bảo giá trị mặc định là 0
NNP_DAEMON_JSON=$(grep "no-new-privileges" /etc/docker/daemon.json 2>/dev/null | grep -c "true" || echo 0)
NNP_DAEMON_FLAG=$(ps -ef | grep dockerd | grep -v grep | grep -c -e "--no-new-privileges" || echo 0)

if [ "$NNP_DAEMON_JSON" -gt 0 ] || [ "$NNP_DAEMON_FLAG" -gt 0 ]; then
  pass "2.15 Docker daemon is configured to restrict new privileges by default"
else
  # Rationale: Giảm thiểu rủi ro từ các bản sao đặc quyền nguy hiểm [7]
  fail "2.15 Docker daemon is NOT configured with --no-new-privileges"
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
