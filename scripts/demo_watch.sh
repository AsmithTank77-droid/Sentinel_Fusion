#!/usr/bin/env bash
# scripts/demo_watch.sh — Live file watcher demo
#
# Starts sentinel watch in directory mode, then drops event files into the
# incoming/ directory every few seconds to simulate a live log feed.
#
# Usage:
#   bash scripts/demo_watch.sh
#
# Requirements:
#   pip install -e .   (or run via: python -m interface.cli watch --dir incoming)

set -euo pipefail

INCOMING="$(dirname "$0")/../incoming"
mkdir -p "$INCOMING"

# Clean up any leftover demo files from a previous run
rm -f "$INCOMING"/winlog_demo*.json "$INCOMING"/nra_demo*.json

echo ""
echo "  Sentinel Watch — Live Demo"
echo "  Dropping event files into: $INCOMING"
echo "  Watch sentinel detect threats in real time."
echo ""

# Start the watcher in the background
sentinel watch --dir "$INCOMING" --interval 3 &
WATCHER_PID=$!

# Give the watcher a moment to start
sleep 2

echo "[demo] Dropping Windows brute-force events..."
cat > "$INCOMING/winlog_demo_01.json" << 'EOF'
[
  {"timestamp":"2026-06-08T10:00:00Z","source_type":"winlog","src_ip":"185.220.101.45","dst_ip":"10.0.0.5","event_type":"authentication_failure","severity":"medium","event_id":4625,"metadata":{"username":"administrator","logon_type":3}},
  {"timestamp":"2026-06-08T10:00:05Z","source_type":"winlog","src_ip":"185.220.101.45","dst_ip":"10.0.0.5","event_type":"authentication_failure","severity":"medium","event_id":4625,"metadata":{"username":"administrator","logon_type":3}},
  {"timestamp":"2026-06-08T10:00:10Z","source_type":"winlog","src_ip":"185.220.101.45","dst_ip":"10.0.0.5","event_type":"authentication_failure","severity":"medium","event_id":4625,"metadata":{"username":"administrator","logon_type":3}},
  {"timestamp":"2026-06-08T10:00:15Z","source_type":"winlog","src_ip":"185.220.101.45","dst_ip":"10.0.0.5","event_type":"authentication_failure","severity":"medium","event_id":4625,"metadata":{"username":"administrator","logon_type":3}},
  {"timestamp":"2026-06-08T10:00:20Z","source_type":"winlog","src_ip":"185.220.101.45","dst_ip":"10.0.0.5","event_type":"authentication_failure","severity":"medium","event_id":4625,"metadata":{"username":"administrator","logon_type":3}},
  {"timestamp":"2026-06-08T10:00:25Z","source_type":"winlog","src_ip":"185.220.101.45","dst_ip":"10.0.0.5","event_type":"authentication_success","severity":"high","event_id":4624,"metadata":{"username":"administrator","logon_type":3}}
]
EOF

sleep 6

echo "[demo] Dropping Nmap scan results..."
cat > "$INCOMING/nra_demo_01.json" << 'EOF'
[
  {"timestamp":"2026-06-08T10:01:00Z","source_type":"nra","src_ip":"185.220.101.45","dst_ip":"10.0.0.5","event_type":"port_scan","severity":"high","metadata":{"port":22,"service":"ssh","state":"open"}},
  {"timestamp":"2026-06-08T10:01:01Z","source_type":"nra","src_ip":"185.220.101.45","dst_ip":"10.0.0.5","event_type":"port_scan","severity":"high","metadata":{"port":3389,"service":"ms-wbt-server","state":"open"}},
  {"timestamp":"2026-06-08T10:01:02Z","source_type":"nra","src_ip":"185.220.101.45","dst_ip":"10.0.0.5","event_type":"port_scan","severity":"medium","metadata":{"port":445,"service":"microsoft-ds","state":"open"}}
]
EOF

sleep 6

echo "[demo] Dropping lateral movement events..."
cat > "$INCOMING/winlog_demo_02.json" << 'EOF'
[
  {"timestamp":"2026-06-08T10:02:00Z","source_type":"winlog","src_ip":"10.0.0.5","dst_ip":"10.0.0.20","event_type":"explicit_credential_logon","severity":"high","event_id":4648,"metadata":{"username":"administrator","target_host":"10.0.0.20"}},
  {"timestamp":"2026-06-08T10:02:30Z","source_type":"winlog","src_ip":"10.0.0.5","dst_ip":"10.0.0.20","event_type":"authentication_success","severity":"medium","event_id":4624,"metadata":{"username":"administrator","logon_type":3}}
]
EOF

sleep 6

echo ""
echo "[demo] Done. Press Ctrl+C to stop the watcher."

# Wait for the watcher to be killed
wait $WATCHER_PID 2>/dev/null || true
