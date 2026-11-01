#!/bin/bash
# Pre-build hook for AES
# Checks if plan is done, validates critical files, loads wake context, runs debt gate

# Auto-configure my-brain gate
if [[ -f "scripts/my-brain-auto-config.sh" ]]; then
	. scripts/my-brain-auto-config.sh
fi

echo "Running pre-build checks..."

# Check if we're in an AES project
if [ ! -f "aes/kanban.md" ]; then
	echo "Error: Not in an AES project (missing aes/kanban.md)"
	exit 1
fi

# Check if plan exists for current ticket
CURRENT_TICKET=$(grep "current_ticket:" aes/kanban.md | awk '{print $2}' | head -1)
if [ -z "$CURRENT_TICKET" ]; then
	echo "Error: No current_ticket found in aes/kanban.md"
	echo "Add 'current_ticket: TXXX' to the kanban frontmatter."
	exit 1
fi

# Check for plan file
PLAN_FILE="aes/tickets/${CURRENT_TICKET}-plan.md"
if [ ! -f "$PLAN_FILE" ]; then
	echo "Error: Plan file not found: $PLAN_FILE"
	echo "Please run '/aes-plan' before building."
	exit 1
fi

# Check if plan is done
if ! grep -q "status: done" "$PLAN_FILE"; then
	echo "Error: Plan is not marked as done in $PLAN_FILE"
	echo "Please complete the plan phase before building."
	exit 1
fi

# Check for critical files
CRITICAL_FILES=("docs/VISION.md" "docs/REQUIREMENTS.md" "docs/ROADMAP.md")
for file in "${CRITICAL_FILES[@]}"; do
	if [ ! -f "$file" ]; then
		echo "Error: Missing critical file: $file"
		exit 1
	fi

	# Check if file is not just a placeholder
	# Match actual placeholder patterns (TBD, TODO, ...), not markdown syntax
	if grep -qE "\[(TBD|TODO|FIXME|XXX|\.\.\.)\]" "$file"; then
		echo "Warning: File $file contains placeholder patterns (TBD/TODO/FIXME/...)"
	fi
done

# Load wake context for current ticket (relevance ranking + open loops)
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  PRE-BUILD: Loading context via make wake"
echo "═══════════════════════════════════════════════════════"
make wake TICKET="$CURRENT_TICKET" 2>&1 || echo "  ⚠  make wake failed — continuing without context"
echo "════════════════════════════════════════════════════════"

# Run epistemic debt gate
echo ""
echo "=================================================="
echo "  PRE-BUILD: Epistemic Debt Gate (make debt-gate)"
echo "=================================================="
make debt-gate 2>&1 || {
	echo "  Epistemic debt gate: BLOCKED"
	echo "  Fix debt metrics or adjust thresholds via env vars:"
	echo "    AES_VERIFICATION_RATE_MIN (default 50)"
	echo "    AES_UNCHECKED_ACS_MAX (default 0)"
	echo "    AES_FATIGUE_RATE_MAX (default 10)"
	echo "    AES_OVERRIDE_MAX (default 5)"
	echo "    AES_AGING_DEBT_MAX (default 10)"
	exit 1
}
echo "  Epistemic debt gate: PASSED"
echo "=================================================="

echo "Pre-build checks passed."
exit 0
