#!/bin/bash

echo "===== CIS DOCKER FULL AUDIT ====="

./audit/01-host-docker-engine-audit.sh
./audit/02-audit-daemon-os-security.sh
./audit/03-image-supply-chain-audit.sh

echo "===== DONE ====="