#!/bin/bash

set -e

mkdir -p report

echo "===== CIS DOCKER FULL AUDIT ====="

echo "[MODULE 1] Host Docker Engine Audit"
bash ./audit/01-host-docker-engine-audit.sh | tee report/module1-host.txt

echo "[MODULE 2] Daemon & OS Security Audit"
bash ./audit/02-audit-daemon-os-security.sh | tee report/module2-daemon.txt

echo "[MODULE 3] Image & Supply Chain Audit"
bash ./audit/03-image-supply-chain-audit.sh | tee report/module3-image.txt

echo ""
echo "===== SUMMARY =====" | tee report/summary.txt

echo "Module 1 (last 20 lines):" | tee -a report/summary.txt
tail -n 20 report/module1-host.txt >> report/summary.txt

echo "" >> report/summary.txt

echo "Module 2 (last 20 lines):" | tee -a report/summary.txt
tail -n 20 report/module2-daemon.txt >> report/summary.txt

echo "" >> report/summary.txt

echo "Module 3 (last 20 lines):" | tee -a report/summary.txt
tail -n 20 report/module3-image.txt >> report/summary.txt

echo ""
echo "===== DONE ====="