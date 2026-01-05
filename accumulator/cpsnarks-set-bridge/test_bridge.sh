#!/bin/bash

# Test script for the file-based bridge
# This script tests the bridge by writing requests and reading responses

set -e

BRIDGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BRIDGE_DIR"

REQUEST_FILE="bridge_request.json"
RESPONSE_FILE="bridge_response.json"
REQUEST_LOCK="bridge_request.lock"
RESPONSE_LOCK="bridge_response.lock"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up test files...${NC}"
    rm -f "$REQUEST_FILE" "$RESPONSE_FILE" "$REQUEST_LOCK" "$RESPONSE_LOCK"
}

trap cleanup EXIT

echo -e "${GREEN}=== Bridge Test Script ===${NC}\n"

# Test 1: Setup Request
echo -e "${YELLOW}Test 1: Setup Request${NC}"
cat > "$REQUEST_FILE" << 'EOF'
{
  "type": "setup",
  "security_level": 128
}
EOF

echo "✓ Created setup request file"
echo "  Request file: $REQUEST_FILE"
echo ""
echo "Now start the bridge in another terminal:"
echo "  cd $BRIDGE_DIR"
echo "  cargo run --release"
echo ""
echo "Press Enter after the bridge is running..."
read -r

# Wait for response
echo "Waiting for response..."
timeout=30
elapsed=0
while [ ! -f "$RESPONSE_FILE" ] && [ $elapsed -lt $timeout ]; do
    sleep 1
    elapsed=$((elapsed + 1))
    echo -n "."
done
echo ""

if [ -f "$RESPONSE_FILE" ]; then
    echo -e "${GREEN}✓ Received response${NC}"
    echo "Response content:"
    cat "$RESPONSE_FILE" | jq '.' 2>/dev/null || cat "$RESPONSE_FILE"
    echo ""
    
    # Check if response indicates success
    if grep -q '"status": "success"' "$RESPONSE_FILE"; then
        echo -e "${GREEN}✓ Setup test PASSED${NC}"
    else
        echo -e "${RED}✗ Setup test FAILED - status not success${NC}"
        exit 1
    fi
else
    echo -e "${RED}✗ No response received within $timeout seconds${NC}"
    exit 1
fi

# Clean up for next test
rm -f "$REQUEST_FILE" "$RESPONSE_FILE" "$REQUEST_LOCK" "$RESPONSE_LOCK"
sleep 2

# Test 2: Prove Request
echo -e "\n${YELLOW}Test 2: Prove Request${NC}"
cat > "$REQUEST_FILE" << 'EOF'
{
  "type": "prove",
  "security_level": 128,
  "element": "12702637924034044211",
  "randomness": "5"
}
EOF

echo "✓ Created prove request file"
echo "Press Enter to continue..."
read -r

# Wait for response
echo "Waiting for response..."
timeout=60
elapsed=0
while [ ! -f "$RESPONSE_FILE" ] && [ $elapsed -lt $timeout ]; do
    sleep 1
    elapsed=$((elapsed + 1))
    echo -n "."
done
echo ""

if [ -f "$RESPONSE_FILE" ]; then
    echo -e "${GREEN}✓ Received response${NC}"
    echo "Response content:"
    cat "$RESPONSE_FILE" | jq '.' 2>/dev/null || cat "$RESPONSE_FILE"
    echo ""
    
    # Check if response indicates success
    if grep -q '"status": "success"' "$RESPONSE_FILE"; then
        echo -e "${GREEN}✓ Prove test PASSED${NC}"
    else
        echo -e "${RED}✗ Prove test FAILED - status not success${NC}"
        exit 1
    fi
else
    echo -e "${RED}✗ No response received within $timeout seconds${NC}"
    exit 1
fi

echo -e "\n${GREEN}=== All Tests Passed! ===${NC}"



