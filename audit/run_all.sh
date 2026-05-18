#!/bin/bash

set -e

mkdir -p report

CSV_FILE="report/cis_report.csv"

# init CSV
echo "module,status,message" > "$CSV_FILE"

echo "===== CIS DOCKER FULL AUDIT ====="

run_module () {

    MODULE_NAME=$1
    SCRIPT=$2
    OUTPUT_FILE=$3

    echo "[RUN] $MODULE_NAME"

    bash "$SCRIPT" | tee "$OUTPUT_FILE" | while read -r line; do

        if echo "$line" | grep -q "\[PASS\]"; then
            echo "$MODULE_NAME,PASS,\"${line#*] }\"" >> "$CSV_FILE"

        elif echo "$line" | grep -q "\[FAIL\]"; then
            echo "$MODULE_NAME,FAIL,\"${line#*] }\"" >> "$CSV_FILE"

        elif echo "$line" | grep -q "\[WARN\]"; then
            echo "$MODULE_NAME,WARN,\"${line#*] }\"" >> "$CSV_FILE"

        fi

    done
}

INDEX=1

for script in ./audit/[0-9][0-9]-*.sh; do

    NAME=$(basename "$script" .sh)

    run_module \
      "module$INDEX" \
      "$script" \
      "report/${NAME}.txt"

    INDEX=$((INDEX+1))

done

echo ""
echo "===== DONE ====="
echo "CSV REPORT: $CSV_FILE"