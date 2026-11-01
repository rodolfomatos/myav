#!/bin/sh
# Pre-commit hook for AES
# Blocks commits if current ticket's verification gate fails
# Bypass requires explicit justification: AES_BYPASS="TICKET:reason" git commit
# All bypasses are logged to aes/metrics/bypass.log with full context

set -e

echo ""
echo "══════════════════════════════════════════════════"
echo "  Pre-Commit Verification Gate"
echo "══════════════════════════════════════════════════"

if [ ! -f "aes/kanban.md" ]; then
	echo "  Not in an AES project — skipping"
	exit 0
fi

# Kanban consistency check before commit — NON-BYPASSABLE
if [ -f "scripts/kanban-check.sh" ] && [ -x "scripts/kanban-check.sh" ]; then
	echo ""
	echo "  Running kanban consistency check..."
	if ! scripts/kanban-check.sh; then
		scripts/gate-blocks.sh log kanban-check 2>/dev/null || true
		echo ""
		echo "  ❌ Kanban check FAILED"
		echo "  Fix kanban inconsistencies before committing."
		exit 1
	fi
fi

CURRENT_TICKET=$(grep "^current_ticket:" aes/kanban.md | head -1 | awk '{print $2}' | tr -d '[:space:]')
if [ -z "$CURRENT_TICKET" ] || [ "$CURRENT_TICKET" = "none" ]; then
	echo "  No current_ticket — skipping verification gate"
	exit 0
fi

VERIFY_SCRIPT="scripts/verify-implementation.sh"
if [ ! -x "$VERIFY_SCRIPT" ]; then
	echo "  ⚠  verify-implementation.sh not found — verification gate SKIPPED"
	echo "  Install: make setup or create scripts/verify-implementation.sh"
	exit 0
fi

# Bypass handling: requires explicit justification
if [ -n "${AES_BYPASS:-}" ]; then
	BYPASS_REASON="$AES_BYPASS"
	if ! echo "$BYPASS_REASON" | grep -q ":"; then
		echo ""
		echo "  ❌ INVALID BYPASS FORMAT"
		echo "  AES_BYPASS must be 'TICKET_ID:justification'"
		echo "  Example: AES_BYPASS=\"T123:hotfix for prod outage\" git commit"
		exit 1
	fi

	BYPASS_TICKET=$(echo "$BYPASS_REASON" | cut -d: -f1)
	BYPASS_JUSTIFICATION=$(echo "$BYPASS_REASON" | cut -d: -f2-)

	if [ "$BYPASS_TICKET" != "$CURRENT_TICKET" ]; then
		echo ""
		echo "  ❌ BYPASS TICKET MISMATCH"
		echo "  Current ticket: $CURRENT_TICKET"
		echo "  Bypass ticket:  $BYPASS_TICKET"
		echo "  Bypass ticket must match current_ticket"
		exit 1
	fi

	# Store bypass info for prepare-commit-msg hook
	mkdir -p .git
	echo "$CURRENT_TICKET:$BYPASS_JUSTIFICATION" >.git/AES_BYPASS

	# Log bypass with full context
	mkdir -p aes/metrics
	BYPASS_LOG="aes/metrics/bypass.log"
	{
		echo "=== BYPASS $(date -Iseconds) ==="
		echo "Ticket: $CURRENT_TICKET"
		echo "User: $(git config user.name) <$(git config user.email)>"
		echo "Justification: $BYPASS_JUSTIFICATION"
		echo "Commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'no commits yet')"
		echo "Branch: $(git branch --show-current 2>/dev/null || echo 'detached')"
		echo "Files: $(git diff --cached --name-only | tr '\n' ' ')"
		echo ""
	} >>"$BYPASS_LOG"

	echo ""
	echo "  ⚠️  BYPASS GRANTED (logged to $BYPASS_LOG)"
	echo "  Ticket: $CURRENT_TICKET"
	echo "  Reason: $BYPASS_JUSTIFICATION"
	echo "  Commit will include bypass trailer"

	exit 0
fi

# Normal verification gate
echo ""
echo "  Running verification gate for $CURRENT_TICKET..."
if ! scripts/verify-implementation.sh "$CURRENT_TICKET"; then
	scripts/gate-blocks.sh log verify-implementation "$CURRENT_TICKET" 2>/dev/null || true
	echo ""
	echo "  ❌ VERIFICATION GATE BLOCKED"
	echo "  Ticket $CURRENT_TICKET has failing acceptance criteria."
	echo "  Fix the issues above before committing."
	echo ""
	echo "  Emergency bypass (requires justification):"
	echo "    AES_BYPASS=\"$CURRENT_TICKET:hotfix for prod outage\" git commit"
	echo "  This will be logged and added to commit message."
	exit 1
fi

echo "  ✅ Verification gate passed for $CURRENT_TICKET"
echo ""
exit 0
