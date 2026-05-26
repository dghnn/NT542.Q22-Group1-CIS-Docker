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

echo "##### CIS Docker Benchmark - Container Runtime Security Audit #####"
echo "Date: $(date)"
echo

# Pre-flight checks
if ! command -v docker >/dev/null 2>&1; then
  fail "Docker is not installed"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  fail "Docker daemon is not running or current user cannot access Docker"
  exit 1
fi

ALL_CONTAINERS=$(docker ps -aq 2>/dev/null || true)
RUNNING_CONTAINERS=$(docker ps -q 2>/dev/null || true)

if [ -z "$ALL_CONTAINERS" ]; then
  warn "No containers found. Most container runtime checks will be skipped."
fi


####### Swarm & Network Isolation

echo "### Network Isolation"

# 5.10 - Ensure that the host's network namespace is not shared
if [ -n "$ALL_CONTAINERS" ]; then
    ALL_PASS=true
    for cid in $ALL_CONTAINERS; do
        NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)
        NET_MODE=$(docker inspect --format '{{ .HostConfig.NetworkMode }}' "$cid" 2>/dev/null)
        if [ "$NET_MODE" = "host" ]; then
            warn "5.10 Ensure that the host's network namespace is not shared: $NAME uses host network; verify if required"
            ALL_PASS=false
        fi
    done
    [ "$ALL_PASS" = true ] && \
    pass "5.10 Ensure that the host's network namespace is not shared: no containers use host network"
else
    warn "5.10 Skipped: no containers found"
fi

# 5.8 - Ensure privileged ports are not mapped within containers
if [ -n "$RUNNING_CONTAINERS" ]; then
  ALL_PASS=true
  for cid in $RUNNING_CONTAINERS; do
    NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)
    PRIV_PORT=$(docker inspect --format '{{json .NetworkSettings.Ports}}' "$cid" 2>/dev/null \
      | grep -oE '"HostPort":"[0-9]+"' | awk -F'"' '{print $4}' \
      | awk '$1+0 < 1024 && $1+0 > 0' | wc -l)
    if [ "$PRIV_PORT" -gt 0 ]; then
      fail "5.8 Ensure privileged ports are not mapped within containers: $NAME maps $PRIV_PORT privileged port(s) (< 1024)"
      ALL_PASS=false
    fi
  done
  [ "$ALL_PASS" = true ] && pass "5.8 Ensure privileged ports are not mapped within containers: no privileged ports mapped"
else
  warn "5.8 Skipped: no running containers found"
fi

####### Container Privilege & Access Controls
echo "### Container Privilege & Access Controls "

# 5.5 - Ensure that privileged containers are not used
if [ -n "$ALL_CONTAINERS" ]; then
  ALL_PASS=true
  for cid in $ALL_CONTAINERS; do
    NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)
    PRIV=$(docker inspect --format '{{ .HostConfig.Privileged }}' "$cid" 2>/dev/null)
    if [ "$PRIV" = "true" ]; then
      fail "5.5 Ensure that privileged containers are not used: $NAME is running in privileged mode"
      ALL_PASS=false
    fi
  done
  [ "$ALL_PASS" = true ] && pass "5.5 Ensure that privileged containers are not used: no privileged containers found"
else
  warn "5.5 Skipped: no containers found"
fi

# 5.16 - Ensure that the host's process namespace is not shared
if [ -n "$ALL_CONTAINERS" ]; then
  for cid in $ALL_CONTAINERS; do
    NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)
    PID_MODE=$(docker inspect --format '{{ .HostConfig.PidMode }}' "$cid" 2>/dev/null)
    INSPECT_EXIT=$?
    # Only WARN if docker inspect actually fails
    if [ $INSPECT_EXIT -ne 0 ]; then
      warn "5.16 Ensure PID namespace isolation: $NAME could not inspect container"
      continue
    fi
    # Normalize empty = default (OK)
    if [ -z "$PID_MODE" ]; then
      PID_MODE="default"
    fi
    # CIS rule check
    if [ "$PID_MODE" = "host" ]; then
      fail "5.16 Ensure PID namespace isolation: $NAME uses host PID namespace"
    else
      pass "5.16 Ensure PID namespace isolation: $NAME uses $PID_MODE PID namespace"
    fi
  done
else
  warn "5.16 Skipped: no containers found"
fi

# 5.18 - Ensure that host devices are not directly exposed to containers
if [ -n "$ALL_CONTAINERS" ]; then
  for cid in $ALL_CONTAINERS; do
    NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)
    DEVICES=$(docker inspect --format '{{ json .HostConfig.Devices }}' "$cid" 2>/dev/null)
    INSPECT_EXIT=$?
    # Handle inspect failure
    if [ $INSPECT_EXIT -ne 0 ]; then
      warn "5.18 Ensure device isolation: $NAME could not inspect container"
      continue
    fi
    # Normalize empty cases
    if [ -z "$DEVICES" ] || [ "$DEVICES" = "null" ] || [ "$DEVICES" = "[]" ]; then
      pass "5.18 Ensure device isolation: $NAME has no host devices exposed"
    else
      fail "5.18 Ensure device isolation: $NAME exposes host devices: $DEVICES"
    fi
  done
else
  warn "5.18 Skipped: no containers found"
fi

####### Resource Limits & Resilience
echo "### Resource Limits & Resilience"

# 5.6 - Ensure sensitive host system directories are not mounted on containers
if [ -n "$ALL_CONTAINERS" ]; then
  SENSITIVE_PATHS="/etc /boot /dev /lib /proc /sys /usr"
  for cid in $ALL_CONTAINERS; do
    NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)
    MOUNTS=$(docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' "$cid" 2>/dev/null)
    FOUND=false
    for spath in $SENSITIVE_PATHS; do
      if echo "$MOUNTS" | grep -qE "(^| )${spath}(/| |$)"; then
        fail "5.6 Ensure sensitive host system directories are not mounted on containers: $NAME mounts '$spath'"
        FOUND=true
      fi
    done
    [ "$FOUND" = false ] && pass "5.6 Ensure sensitive host system directories are not mounted on containers: $NAME has no sensitive mounts"
  done
else
  warn "5.6 Skipped: no containers found"
fi

# 5.11 - Ensure that the memory usage for containers is limited
if [ -n "$ALL_CONTAINERS" ]; then
  for cid in $ALL_CONTAINERS; do
    NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)
    MEM=$(docker inspect --format '{{ .HostConfig.Memory }}' "$cid" 2>/dev/null)
    if [ -z "$MEM" ] || [ "$MEM" = "0" ]; then
      fail "5.11 Ensure that the memory usage for containers is limited: $NAME has no memory limit"
    else
      MEM_MB=$(( MEM / 1024 / 1024 ))
      pass "5.11 Ensure that the memory usage for containers is limited: $NAME memory limit=${MEM_MB}MB"
    fi
  done
else
  warn "5.11 Skipped: no containers found"
fi

# 5.12 - Ensure that CPU priority is set appropriately on containers
if [ -n "$ALL_CONTAINERS" ]; then
  for cid in $ALL_CONTAINERS; do
    NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)
    CPU_SHARES=$(docker inspect --format '{{ .HostConfig.CpuShares }}' "$cid" 2>/dev/null)
    if [ -z "$CPU_SHARES" ] || [ "$CPU_SHARES" = "0" ]; then
      fail "5.12 Ensure that CPU priority is set appropriately on containers: $NAME has no CPU shares configured"
    else
      pass "5.12 Ensure that CPU priority is set appropriately on containers: $NAME CPU shares=$CPU_SHARES"
    fi
  done
else
  warn "5.12 Skipped: no containers found"
fi

# 5.15 - Ensure that the 'on-failure' container restart policy is set to '5'
if [ -n "$ALL_CONTAINERS" ]; then
  for cid in $ALL_CONTAINERS; do
    NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)
    RESTART_NAME=$(docker inspect --format '{{ .HostConfig.RestartPolicy.Name }}' "$cid" 2>/dev/null)
    RETRY_COUNT=$(docker inspect --format '{{ .HostConfig.RestartPolicy.MaximumRetryCount }}' "$cid" 2>/dev/null)
    if [ "$RESTART_NAME" = "on-failure" ] && [ -n "$RETRY_COUNT" ] && [ "$RETRY_COUNT" -gt 0 ] && [ "$RETRY_COUNT" -le 5 ]; then
      pass "5.15 Ensure that the 'on-failure' container restart policy is set to '5': $NAME policy=on-failure MaxRetry=$RETRY_COUNT"
    elif [ "$RESTART_NAME" = "always" ] || [ "$RESTART_NAME" = "unless-stopped" ]; then
      fail "5.15 Ensure that the 'on-failure' container restart policy is set to '5': $NAME policy='$RESTART_NAME' allows unlimited restarts"
    else
      warn "5.15 Ensure that the 'on-failure' container restart policy is set to '5': $NAME policy='$RESTART_NAME' (MaxRetry=$RETRY_COUNT) — review manually"
    fi
  done
else
  warn "5.15 Skipped: no containers found"
fi

echo

####### Filesystem & Identity Isolation
echo "### Filesystem & Identity Isolation"

# 5.20 - Ensure mount propagation mode is not set to shared
if [ -n "$ALL_CONTAINERS" ]; then
  for cid in $ALL_CONTAINERS; do
    NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)
    BAD_PROP=$(docker inspect --format '{{range .Mounts}}{{.Propagation}} {{end}}' "$cid" 2>/dev/null \
      | grep -owE 'shared|rshared|slave|rslave' | wc -l)
    if [ "$BAD_PROP" -gt 0 ]; then
      fail "5.20 Ensure mount propagation mode is not set to shared: $NAME has shared/slave mount propagation"
    else
      pass "5.20 Ensure mount propagation mode is not set to shared: $NAME uses private/rprivate propagation"
    fi
  done
else
  warn "5.20 Skipped: no containers found"
fi

# 5.31 - Ensure that the host's user namespaces are not shared
if [ -n "$ALL_CONTAINERS" ]; then
  ALL_PASS=true
  for cid in $ALL_CONTAINERS; do
    NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)
    USERNS=$(docker inspect --format '{{ .HostConfig.UsernsMode }}' "$cid" 2>/dev/null)
    if [ "$USERNS" = "host" ]; then
      fail "5.31 Ensure that the host's user namespaces are not shared: $NAME uses host user namespace"
      ALL_PASS=false
    fi
  done
  [ "$ALL_PASS" = true ] && pass "5.31 Ensure that the host's user namespaces are not shared: no containers share host user namespace"
else
  warn "5.31 Skipped: no containers found"
fi

# 5.32 - Ensure that the Docker socket is not mounted inside any containers
if [ -n "$ALL_CONTAINERS" ]; then
  ALL_PASS=true
  for cid in $ALL_CONTAINERS; do
    NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)
    SOCK=$(docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' "$cid" 2>/dev/null \
      | grep -c 'docker.sock' || true)
    if [ "$SOCK" -gt 0 ]; then
      fail "5.32 Ensure that the Docker socket is not mounted inside any containers: $NAME mounts docker.sock"
      ALL_PASS=false
    fi
  done
  [ "$ALL_PASS" = true ] && pass "5.32 Ensure that the Docker socket is not mounted inside any containers: no containers mount docker.sock"
else
  warn "5.32 Skipped: no containers found"
fi

echo

####### Container Health & Observability
echo "### Container Health & Observability"

# 5.27 - Ensure that container health is checked at runtime
if [ -n "$RUNNING_CONTAINERS" ]; then
  for cid in $RUNNING_CONTAINERS; do
    NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)
    HEALTH=$(docker inspect --format '{{ .State.Health.Status }}' "$cid" 2>/dev/null)
    if [ "$HEALTH" = "healthy" ]; then
      pass "5.27 Ensure that container health is checked at runtime: $NAME status=healthy"
    elif [ "$HEALTH" = "unhealthy" ]; then
      fail "5.27 Ensure that container health is checked at runtime: $NAME status=unhealthy"
    elif [ -z "$HEALTH" ]; then
      warn "5.27 Ensure that container health is checked at runtime: $NAME has no HEALTHCHECK configured"
    else
      warn "5.27 Ensure that container health is checked at runtime: $NAME status=$HEALTH"
    fi
  done
else
  warn "5.27 Skipped: no running containers found"
fi

echo
echo "===== SUMMARY ====="
echo "PASS : $PASS"
echo "FAIL : $FAIL"
echo "WARN : $WARN"
echo "INFO : $INFO"