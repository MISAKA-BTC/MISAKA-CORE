#!/bin/bash
# SR6 Devnet Health Check
VALIDATORS="133.167.126.213 160.16.131.119 49.212.166.172"
echo "=== SR6 Health Check $(date) ==="
for IP in $VALIDATORS; do
    echo -n "$IP: "
    curl -s --max-time 5 http://$IP:3000/api/health || echo "UNREACHABLE"
    echo ""
done
