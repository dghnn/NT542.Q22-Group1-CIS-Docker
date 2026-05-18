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

echo "### Swarm & Network Isolation"
# 5.1 - Ensure swarm mode is not Enabled, if not needed
SWARM_STATE=$(docker info --format '{{ .Swarm.LocalNodeState }}' 2>/dev/null)
if [ "$SWARM_STATE" = "inactive" ] || [ -z "$SWARM_STATE" ]; then
  pass "5.1 Ensure swarm mode is not Enabled, if not needed: Swarm is inactive"
else
  warn "5.1 Ensure swarm mode is not Enabled, if not needed: Swarm is enabled ($SWARM_STATE). Manual verification required."
fi

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

# 5.14 - Ensure that incoming container traffic is bound to a specific host interface
if [ -n "$RUNNING_CONTAINERS" ]; then
  for cid in $RUNNING_CONTAINERS; do
    NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)

    BINDS=$(docker inspect --format '{{json .NetworkSettings.Ports}}' "$cid" 2>/dev/null \
      | grep -oE '"HostIp":"[^"]*"' \
      | awk -F'"' '{print $4}' \
      | sort -u)

    if echo "$BINDS" | grep -qx '0\.0\.0\.0'; then
      fail "5.14 Ensure that incoming container traffic is bound to a specific host interface: $NAME has port(s) bound to 0.0.0.0"
    elif [ -z "$BINDS" ]; then
      pass "5.14 Ensure that incoming container traffic is bound to a specific host interface: $NAME has no published ports"
    else
      pass "5.14 Ensure that incoming container traffic is bound to specific interface(s): $(echo "$BINDS" | tr '\n' ' ')"
    fi
  done
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

# 5.9 - Ensure that only needed ports are open on the container
if [ -n "$RUNNING_CONTAINERS" ]; then
  ALL_PASS=true
  for cid in $RUNNING_CONTAINERS; do
    NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)
    HOST_PORTS=$(docker inspect --format \
'{{range $p,$v := .NetworkSettings.Ports}}{{if $v}}{{range $v}}{{println .HostPort}}{{end}}{{end}}{{end}}' \
"$cid" 2>/dev/null)
    if [ -n "$HOST_PORTS" ]; then
      warn "5.9 Ensure that only needed ports are open on the container: $NAME exposes ports below (manual review required)"
      echo "$HOST_PORTS" | awk 'NF'
      ALL_PASS=false
    else
      pass "5.9 Ensure that only needed ports are open on the container: $NAME has no published ports"
    fi
  done
  if [ "$ALL_PASS" = true ]; then
    pass "5.9 Ensure that only needed ports are open on the container: all containers have no unnecessary exposed ports"
  fi
else
  pass "5.9 Skipped: no running containers found"
fi
echo

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

# 5.22 - Ensure the default seccomp profile is not Disabled
# 5.26 - Ensure that the container is restricted from acquiring additional privileges
if [ -n "$ALL_CONTAINERS" ]; then
  for cid in $ALL_CONTAINERS; do
    NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)
    SEC_OPT=$(docker inspect --format '{{ .HostConfig.SecurityOpt }}' "$cid" 2>/dev/null)

    if echo "$SEC_OPT" | grep -q 'seccomp=unconfined'; then
      fail "5.22 Ensure the default seccomp profile is not Disabled: $NAME has seccomp=unconfined"
    else
      pass "5.22 Ensure the default seccomp profile is not Disabled: $NAME seccomp profile is active"
    fi

    if echo "$SEC_OPT" | grep -q 'no-new-privileges'; then
      pass "5.26 Ensure that the container is restricted from acquiring additional privileges: $NAME has no-new-privileges"
    else
      fail "5.26 Ensure that the container is restricted from acquiring additional privileges: $NAME is missing no-new-privileges"
    fi
  done
else
  warn "5.22/5.26 Skipped: no containers found"
fi
echo

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

# 5.19 - Ensure that the default ulimit is overwritten at runtime if needed
DAEMON_ULIMITS_RAW=""
if [ -f /etc/docker/daemon.json ] && command -v python3 >/dev/null 2>&1; then
  DAEMON_ULIMITS_RAW=$(python3 -c "
import json
try:
    d = json.load(open('/etc/docker/daemon.json'))
    ul = d.get('default-ulimits', {})
    parts = ['%s=%s:%s' % (n, v.get('Soft',''), v.get('Hard','')) for n, v in sorted(ul.items())]
    print(' '.join(parts))
except: pass
" 2>/dev/null)
fi

if [ -n "$ALL_CONTAINERS" ]; then
  for cid in $ALL_CONTAINERS; do
    NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)
    ULIMITS=$(docker inspect --format '{{ .HostConfig.Ulimits }}' "$cid" 2>/dev/null)

    if [ "$ULIMITS" = "<no value>" ] || [ "$ULIMITS" = "[]" ] || [ -z "$ULIMITS" ]; then
      pass "5.19 Ensure that the default ulimit is overwritten at runtime if needed: $NAME inherits daemon defaults (no override)"
      continue
    fi

    NOFILE_HARD=$(echo "$ULIMITS" | grep -oE 'nofile=[0-9]+:[0-9]+' | cut -d: -f2 || true)
    if [ -n "$NOFILE_HARD" ] && [ "$NOFILE_HARD" -gt 65536 ] 2>/dev/null; then
      fail "5.19 Ensure that the default ulimit is overwritten at runtime if needed: $NAME nofile hard limit ($NOFILE_HARD) exceeds safe threshold (65536)"
      continue
    fi

    if [ -n "$DAEMON_ULIMITS_RAW" ]; then
      CONTAINER_NORM=$(echo "$ULIMITS" | tr -d '[]' | tr ' ' '\n' | sort | tr '\n' ' ' | xargs)
      DAEMON_NORM=$(echo "$DAEMON_ULIMITS_RAW" | tr ' ' '\n' | sort | tr '\n' ' ' | xargs)
      if [ "$CONTAINER_NORM" = "$DAEMON_NORM" ]; then
        pass "5.19 Ensure that the default ulimit is overwritten at runtime if needed: $NAME ulimits match daemon defaults"
      else
        warn "5.19 Ensure that the default ulimit is overwritten at runtime if needed: $NAME has custom ulimits differing from daemon defaults: $ULIMITS"
      fi
    else
      warn "5.19 Ensure that the default ulimit is overwritten at runtime if needed: $NAME ulimits set: $ULIMITS (verify against daemon defaults)"
    fi
  done
else
  warn "5.19 Skipped: no containers found"
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

# 5.28 - Ensure that Docker commands always make use of the latest version of their image
if [ -n "$ALL_CONTAINERS" ]; then
  for cid in $ALL_CONTAINERS; do
    NAME=$(docker inspect --format '{{ .Name }}' "$cid" 2>/dev/null)
    IMAGE_TAG=$(docker inspect --format '{{ .Config.Image }}' "$cid" 2>/dev/null)
    if echo "$IMAGE_TAG" | grep -qE ':latest$|^[^:]+$'; then
      warn "5.28 Ensure that Docker commands always make use of the latest version of their image: $NAME uses unversioned/':latest' tag ($IMAGE_TAG) — pin to an explicit version or digest"
    else
      pass "5.28 Ensure that Docker commands always make use of the latest version of their image: $NAME uses explicit tag ($IMAGE_TAG)"
    fi
  done
else
  warn "5.28 Skipped: no containers found"
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