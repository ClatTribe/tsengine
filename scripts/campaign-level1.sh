#!/bin/bash
# CAMPAIGN RUNNER — all 33 remaining level-1 challenges in sequence
# Config: v7 best-known (PXE + COMPACT + 20m timeout)
# Per-challenge: sandbox reap + cache prune between runs
# Abort: 3 consecutive infra failures → NEEDS-ATTENTION marker
cd /Users/ashish/Downloads/cowork/tsengine

export TSENGINE_LLM_OPENCODE=http://127.0.0.1:44551
export TSENGINE_LLM_OPENCODE_PASSWORD=e2epass
export TSENGINE_LLM_OPENCODE_MODEL=opencode/x-preview-f-free
export TSENGINE_SANDBOX_IMAGE=tsengine/sandbox:e2e2
export TSENGINE_ACTIVE_EXPLOIT=1
export TSENGINE_AGENT_PXE=1
export TSENGINE_AGENT_COMPACT=1
export TSENGINE_XBOW_KEEP=1
unset LLM_API_KEY ANTHROPIC_API_KEY TSENGINE_FLEET_GAPFILL

LEDGER=/tmp/e2e/campaign-level1-ledger.jsonl
OUT=/tmp/e2e/campaign-level1-results
LOG=/tmp/e2e/campaign-level1.log
IDS=$(cat /tmp/e2e/all-level1.txt | tr '\n' ',' | sed 's/,$//')
# Remove already-attempted from B0/v6/v7 dev set
DONE="XBEN-005-24,XBEN-006-24,XBEN-009-24,XBEN-013-24,XBEN-019-24,XBEN-020-24,XBEN-021-24,XBEN-024-24,XBEN-026-24,XBEN-031-24,XBEN-032-24,XBEN-033-24"
IDS=$(python3 -c "
done='''$DONE'''.split(',')
all_ids='''$IDS'''.split(',')
remaining=[x for x in all_ids if x not in done]
print(','.join(remaining))
")

echo "[$(date)] campaign starting: $(echo "$IDS" | tr ',' '\n' | wc -l | tr -d ' ') challenge(s)" >> $LOG

consec_zero=0
for ID in ${IDS//,/ }; do
  if [ $consec_zero -ge 3 ]; then
    echo "[$(date +%H:%M)] ABORT: 3 consecutive 0-turn stalls — brain throttle window" >> $LOG
    break
  fi

  echo "[$(date +%H:%M)] $ID …" >> $LOG

  ./bin/tsbench xbow \
    --binary ./bin/tsengine \
    --suite /Users/ashish/Downloads/cowork/validation-benchmarks \
    --only "$ID" \
    --mode investigate --timeout 20m --attempts 2 --resume \
    --ledger "$LEDGER" \
    --out "$OUT"

  # check result
  last_note=$(grep "\"id\":\"$ID\"" "$LEDGER" 2>/dev/null | tail -1 | python3 -c "import json,sys; print(json.loads(sys.stdin.read()).get('note',''))" 2>/dev/null)

  if echo "$last_note" | grep -q "0 turn"; then
    consec_zero=$((consec_zero + 1))
  else
    consec_zero=0
  fi

  # reap + prune between challenges
  docker rm -f $(docker ps -q --filter ancestor=tsengine/sandbox:e2e2) >/dev/null 2>&1
  docker builder prune -f --keep-storage 3GB >/dev/null 2>&1

  free_gb=$(df -g / | tail -n 1 | awk '{print $4}')
  if [ "$free_gb" -lt 25 ]; then
    echo "[$(date +%H:%M)] DISK WARNING: ${free_gb}Gi free" >> $LOG
    docker system prune -f >/dev/null 2>&1
  fi
done

echo "" >> $LOG
echo "=== FINAL AUTOPSY ===" >> $LOG
python3 scripts/xbow_autopsy.py "$LEDGER" "$(dirname $LEDGER)/artifacts" >> $LOG 2>&1
echo "[$(date)] campaign complete" >> $LOG
