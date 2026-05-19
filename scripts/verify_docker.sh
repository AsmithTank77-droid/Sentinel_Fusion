#!/usr/bin/env bash
# scripts/verify_docker.sh — end-to-end Docker verification
# Usage: bash scripts/verify_docker.sh
set -euo pipefail

API="http://localhost:8000/api/v1"
PASS=0
FAIL=0

green() { printf '\033[32m✓ %s\033[0m\n' "$1"; }
red()   { printf '\033[31m✗ %s\033[0m\n' "$1"; FAIL=$((FAIL+1)); }
info()  { printf '\033[36m→ %s\033[0m\n' "$1"; }

check() {
  local label="$1" url="$2" expected="$3"
  local body
  body=$(curl -sf "$url" 2>/dev/null) || { red "$label (request failed)"; return; }
  if echo "$body" | grep -q "$expected"; then
    green "$label"
    PASS=$((PASS+1))
  else
    red "$label (expected '$expected' in response)"
    echo "  Got: $(echo "$body" | head -c 200)"
  fi
}

# ── 1. Build and start ────────────────────────────────────────────────────────
info "Building and starting containers..."
docker compose up --build -d

# ── 2. Wait for healthcheck to pass ──────────────────────────────────────────
info "Waiting for API to be healthy (up to 30s)..."
for i in $(seq 1 30); do
  if curl -sf "$API/health" >/dev/null 2>&1; then
    green "Container is healthy (${i}s)"
    PASS=$((PASS+1))
    break
  fi
  if [ "$i" -eq 30 ]; then
    red "Container failed to become healthy after 30s"
    docker compose logs sentinel
    docker compose down
    exit 1
  fi
  sleep 1
done

# ── 3. Endpoint smoke tests ───────────────────────────────────────────────────
info "Running endpoint checks..."

check "GET /health returns ok"          "$API/health"           '"status":"ok"'
check "GET /status returns totals"      "$API/status"           '"total_events"'
check "GET /alerts returns list"        "$API/alerts"           '[]'
check "GET /events returns list"        "$API/events"           '[]'
check "GET /cases returns list"         "$API/cases"            '[]'
check "GET /scores/hosts returns list"  "$API/scores/hosts"     '[]'
check "GET /pipeline/runs returns list" "$API/pipeline/runs"    '[]'

# ── 4. Pipeline run ───────────────────────────────────────────────────────────
info "Running pipeline with mock attack data..."
RUN_BODY=$(curl -sf -X POST "$API/pipeline/run" \
  -H "Content-Type: application/json" \
  -d '{
    "mock": [{
      "timestamp": "2026-05-19T10:00:00Z",
      "src_ip": "185.220.101.45",
      "dst_ip": "10.0.0.5",
      "event_type": "lateral_movement",
      "severity": "high"
    }]
  }' 2>/dev/null) || { red "POST /pipeline/run failed"; RUN_BODY="{}"; }

if echo "$RUN_BODY" | grep -q '"run_id"'; then
  green "POST /pipeline/run returned run_id"
  PASS=$((PASS+1))
  RUN_ID=$(echo "$RUN_BODY" | grep -o '"run_id":"[^"]*"' | cut -d'"' -f4)
  info "Run ID: $RUN_ID"
else
  red "POST /pipeline/run missing run_id"
  echo "  Got: $(echo "$RUN_BODY" | head -c 300)"
fi

# ── 5. Intel lookup ───────────────────────────────────────────────────────────
check "GET /intel/ip/185.220.101.45"   "$API/intel/ip/185.220.101.45"  '"is_malicious"'

# ── 6. Dashboard reachable ────────────────────────────────────────────────────
info "Checking dashboard..."
HTTP_CODE=$(curl -so /dev/null -w "%{http_code}" "http://localhost:8000/dashboard")
if [ "$HTTP_CODE" = "200" ]; then
  green "Dashboard returns HTTP 200"
  PASS=$((PASS+1))
else
  red "Dashboard returned HTTP $HTTP_CODE"
fi

# ── 7. Teardown ───────────────────────────────────────────────────────────────
info "Stopping containers..."
docker compose down

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────"
printf "Results: \033[32m%d passed\033[0m, \033[31m%d failed\033[0m\n" "$PASS" "$FAIL"
echo "────────────────────────────────"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
