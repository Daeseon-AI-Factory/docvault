#!/bin/bash
# DocVault Pre-Deployment Verification Script
# Run this EVERY TIME before deploying. If any step fails, DO NOT deploy.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "================================================"
echo "  DocVault Pre-Deployment Verification"
echo "================================================"
echo ""

FAIL=0

# Step 1: Build check
echo -n "[1/5] Building all packages... "
if go build ./... 2>/dev/null; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    FAIL=1
fi

# Step 2: Vet
echo -n "[2/5] Running go vet... "
if go vet ./... 2>/dev/null; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    FAIL=1
fi

# Step 3: Unit tests
echo -n "[3/5] Running unit tests... "
TEST_OUTPUT=$(go test ./... -count=1 2>&1)
TEST_RESULT=$?
PASS_COUNT=$(echo "$TEST_OUTPUT" | grep -c "^ok" || true)
FAIL_COUNT=$(echo "$TEST_OUTPUT" | grep -c "^FAIL" || true)

if [ $TEST_RESULT -eq 0 ]; then
    echo -e "${GREEN}PASS${NC} ($PASS_COUNT packages)"
else
    echo -e "${RED}FAIL${NC} ($FAIL_COUNT packages failed)"
    echo "$TEST_OUTPUT" | grep "FAIL"
    FAIL=1
fi

# Step 4: Binary builds
echo -n "[4/5] Building server binary... "
if go build -o /dev/null ./cmd/server 2>/dev/null; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    FAIL=1
fi

echo -n "       Building clipagent binary... "
if go build -o /dev/null ./cmd/clipagent 2>/dev/null; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    FAIL=1
fi

# Step 5: File integrity
echo -n "[5/5] Checking required files... "
MISSING=""
for f in \
    "internal/database/migrations/001_users.up.sql" \
    "internal/database/migrations/002_folders_files.up.sql" \
    "internal/database/migrations/003_audit_logs.up.sql" \
    "internal/database/migrations/004_endpoint_events.up.sql" \
    "internal/database/migrations/005_alerts.up.sql" \
    "internal/database/migrations/006_encryption_keys.up.sql" \
    "internal/database/migrations/007_endpoint_agents.up.sql" \
    "internal/web/static/htmx.min.js" \
    "internal/web/static/style.css" \
    "internal/web/templates/layout.html" \
    "internal/web/templates/login.html" \
    "deploy/osquery/osquery.conf" \
    "deploy/nginx/docvault.conf" \
    "deploy/systemd/docvault.service" \
    "deploy/backup/backup.sh" \
    ".env.example"; do
    if [ ! -f "$f" ]; then
        MISSING="$MISSING $f"
    fi
done

if [ -z "$MISSING" ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC} — missing:$MISSING"
    FAIL=1
fi

# Summary
echo ""
echo "================================================"
if [ $FAIL -eq 0 ]; then
    echo -e "  ${GREEN}ALL CHECKS PASSED — ready to deploy${NC}"
else
    echo -e "  ${RED}CHECKS FAILED — DO NOT DEPLOY${NC}"
fi
echo "================================================"

exit $FAIL
