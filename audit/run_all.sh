#!/bin/bash

set -e

mkdir -p report

CSV_FILE="report/cis_report.csv"

# init CSV
echo "module,status,message" > $CSV_FILE

echo "===== CIS DOCKER FULL AUDIT ====="

run_module () {
    MODULE_NAME=$1
    SCRIPT=$2
    OUTPUT_FILE=$3

    echo "[RUN] $MODULE_NAME"

    bash "$SCRIPT" | tee "$OUTPUT_FILE" | while read line; do

        if echo "$line" | grep -q "\[PASS\]"; then
            echo "$MODULE_NAME,PASS,\"${line#*] }\"" >> $CSV_FILE

        elif echo "$line" | grep -q "\[FAIL\]"; then
            echo "$MODULE_NAME,FAIL,\"${line#*] }\"" >> $CSV_FILE

        elif echo "$line" | grep -q "\[WARN\]"; then
            echo "$MODULE_NAME,WARN,\"${line#*] }\"" >> $CSV_FILE
        fi

    done
}

run_module "module1" "./audit/01-host-docker-engine-audit.sh" "report/module1-host.txt"
run_module "module2" "./audit/02-audit-daemon-os-security.sh" "report/module2-daemon.txt"
run_module "module3" "./audit/03-image-supply-chain-audit.sh" "report/module3-image.txt"

echo ""
echo "===== DONE ====="
echo "CSV REPORT: report/cis_report.csv"