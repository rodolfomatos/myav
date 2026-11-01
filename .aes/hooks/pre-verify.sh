#!/bin/bash
# Pre-verify hook for AES
# Confirms build phase is complete before verification starts

# Auto-configure my-brain gate
if [[ -f "scripts/my-brain-auto-config.sh" ]]; then
	. scripts/my-brain-auto-config.sh
fi

echo "Running pre-verify checks..."

# Check if we're in an AES project
if [ ! -f "aes/kanban.md" ]; then
	echo "Error: Not in an AES project (missing aes/kanban.md)"
	exit 1
fi

# Get current ticket from kanban
CURRENT_TICKET=$(grep "current_ticket:" aes/kanban.md | awk '{print $2}' | head -1)
if [ -z "$CURRENT_TICKET" ]; then
	echo "Error: No current_ticket found in aes/kanban.md"
	exit 1
fi

# Check for build file
BUILD_FILE="aes/tickets/${CURRENT_TICKET}-build.md"
if [ ! -f "$BUILD_FILE" ]; then
	echo "Error: Build file not found: $BUILD_FILE"
	echo "Please run '/aes-build' before verifying."
	exit 1
fi

# Check if build is done
if ! grep -q "status: done" "$BUILD_FILE"; then
	echo "Error: Build phase not complete (status != done) in $BUILD_FILE"
	exit 1
fi

# Load wake context for current ticket
echo ""
echo "=================================================="
echo "  PRE-VERIFY: Loading context via make wake"
echo "=================================================="
make wake TICKET="$CURRENT_TICKET" 2>&1 || echo "  Warning: make wake failed — continuing without context"
echo "=================================================="
echo ""

# ILHA context — inject active memory islands
echo ""
echo "=================================================="
echo "  PRE-VERIFY: ILHA Memory Context"
echo "=================================================="
python3 -m aes.gf.wake --tarefa "$CURRENT_TICKET" 2>&1 || echo "  (ILHA context unavailable)"
echo "=================================================="
echo ""

# Epistemic debt gate
echo ""
echo "=================================================="
echo "  PRE-VERIFY: Epistemic Debt Gate (make debt-gate)"
echo "=================================================="
make debt-gate 2>&1 || {
	scripts/gate-blocks.sh log debt-gate "$CURRENT_TICKET" 2>/dev/null || true
	echo "  Epistemic debt gate: FAILED — thresholds exceeded"
	exit 1
}
echo "  Epistemic debt gate: PASSED"
echo "=================================================="
echo ""

# T291: mechanized pre-verify gate — verify.md must carry ACs + evidence
echo ""
echo "=================================================="
echo "  PRE-VERIFY: AC/Evidence Gate (make verify-ac-evidence)"
echo "=================================================="
make verify-ac-evidence TICKET="$CURRENT_TICKET" 2>&1 || {
	scripts/gate-blocks.sh log verify-ac-evidence "$CURRENT_TICKET" 2>/dev/null || true
	echo "  AC/Evidence gate: FAILED — add acceptance criteria + evidence to ${CURRENT_TICKET}-verify.md"
	exit 1
}
echo "  AC/Evidence gate: PASSED"
echo "=================================================="
echo ""

echo "Pre-verify checks passed."
exit 0
