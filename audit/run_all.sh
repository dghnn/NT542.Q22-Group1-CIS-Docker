#!/bin/bash

echo "===== CIS Docker Audit ====="

echo "[CHECK] Containers running:"
docker ps

echo
echo "[CHECK] Privileged containers:"
docker ps --quiet | xargs docker inspect \
--format '{{ .Name }}: {{ .HostConfig.Privileged }}'

echo
echo "[CHECK] no-new-privileges:"
docker ps --quiet | xargs docker inspect \
--format '{{ .Name }}: {{ .HostConfig.SecurityOpt }}'