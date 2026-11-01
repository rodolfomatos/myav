#!/bin/bash
# Pre-review hook for AES
# Requires verification to be completed with pass verdict and diffstory

echo "Running pre-review checks..."

# Check if we're in an AES project
if [ ! -f "aes/kanban.md" ]; then
	echo "Error: Not in an AES project (missing aes/kanban.md)"
	exit 1
fi

# Check if verification exists for current ticket
CURRENT_TICKET=$(grep "current_ticket:" aes/kanban.md | awk '{print $2}' | head -1)
if [ -z "$CURRENT_TICKET" ]; then
	echo "Error: No current_ticket found in aes/kanban.md"
	echo "Add 'current_ticket: TXXX' to the kanban frontmatter."
	exit 1
fi

# Check for verify file
VERIFY_FILE="aes/tickets/${CURRENT_TICKET}-verify.md"
if [ ! -f "$VERIFY_FILE" ]; then
	echo "Error: Verify file not found: $VERIFY_FILE"
	echo "Please run '/aes-verify' before requesting review."
	exit 1
fi

# Check if verify has verdict: pass
if ! grep -q "verdict: pass" "$VERIFY_FILE"; then
	echo "Error: Verification does not have verdict: pass in $VERIFY_FILE"
	echo "Please fix issues and re-run verification."
	exit 1
fi

# Check if diffstory is written in build file
BUILD_FILE="aes/tickets/${CURRENT_TICKET}-build.md"
if [ ! -f "$BUILD_FILE" ]; then
	echo "Error: Build file not found: $BUILD_FILE"
	echo "Please run '/aes-build' before requesting review."
	exit 1
fi
if ! grep -q "^## Diffstory" "$BUILD_FILE"; then
	echo "Error: Diffstory section not found in $BUILD_FILE"
	echo "The build output must include a '## Diffstory' section."
	exit 1
fi

# Load wake context for current ticket
echo ""
echo "=================================================="
echo "  PRE-REVIEW: Loading context via make wake"
echo "=================================================="
make wake TICKET="$CURRENT_TICKET" 2>&1 || echo "  Warning: make wake failed — continuing without context"
echo "=================================================="
echo ""

# ILHA context — inject active memory islands
echo ""
echo "=================================================="
echo "  PRE-REVIEW: ILHA Memory Context"
echo "=================================================="
python3 -m aes.gf.wake --tarefa "$CURRENT_TICKET" 2>&1 || echo "  (ILHA context unavailable)"
echo "=================================================="
echo ""

# Epistemic debt gate
echo ""
echo "=================================================="
echo "  PRE-REVIEW: Epistemic Debt Gate (make debt-gate)"
echo "=================================================="
make debt-gate 2>&1 || {
	echo "  Epistemic debt gate: FAILED — thresholds exceeded"
	exit 1
}
echo "  Epistemic debt gate: PASSED"
echo "=================================================="
echo ""

# GF can_promote gate — block if HIGH/CRITICAL loops open
echo ""
echo "══════ GF Epistemic Gate (can_promote) ══════"
if python3 -c "
import sys; sys.path.insert(0, '.')
from aes.gf.loop_store import can_promote
ok, blocking = can_promote(min_criticality='HIGH')
if ok:
    print('can_promote: YES')
    sys.exit(0)
else:
    print('can_promote: NO — blocking loops:')
    for b in blocking:
        sev = b.get('criticality', '?')
        bid = b.get('id', '?')
        desc = b.get('description', 'no description')
        print(f'  [{sev}] {bid}: {desc}')
    sys.exit(1)
" 2>&1; then
	echo "GF gate: PASS"
else
	echo "GF gate: BLOCKED — resolve loops before review"
	echo "Tip: make gf-loop-status to inspect open loops"
	echo "Tip: Consider /grilo transparente to bypass GF"
	exit 1
fi

# Hostile Analysis Content Lint (WARNING only - non-blocking)
echo ""
echo "=================================================="
echo "  PRE-REVIEW: Hostile Analysis Content Lint"
echo "=================================================="
REVIEW_FILE="aes/tickets/${CURRENT_TICKET}-review.md"
if [ -f "$REVIEW_FILE" ]; then
	if python3 scripts/hostile_analysis_lint.py "$REVIEW_FILE" 2>&1; then
		echo "Hostile Analysis Lint: PASS"
	else
		echo "WARNING: Hostile Analysis Lint — review lacks references to real repository files"
		echo "         (Currently WARNING only — may become BLOCKER in future)"
	fi
else
	echo "WARNING: Review file not found: $REVIEW_FILE — skipping lint"
fi
echo "=================================================="
echo ""

echo ""
echo "Pre-review checks passed."
exit 0
