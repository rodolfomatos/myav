#!/bin/bash
# Pre-merge hook for AES
# Checks diff size, forbidden files, and ensures all phases are complete

echo "Running pre-merge checks..."

# Check if we're in an AES project
if [ ! -f "aes/kanban.md" ]; then
	echo "Error: Not in an AES project (missing aes/kanban.md)"
	exit 1
fi

# Check if we're in a git repository
if ! git rev-parse --git-dir &>/dev/null; then
	echo "Error: Not in a git repository"
	exit 1
fi

# Check for forbidden files in changes
FORBIDDEN_PATTERNS=(
	"*.key"
	"*.pem"
	"*.env"
	".env*"
	"secrets.*"
	"*secret*"
	"id_rsa"
	"id_dsa"
)

echo "Checking for forbidden files in changes..."
for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
	if git diff --cached --name-only | grep -q "$pattern"; then
		echo "Error: Forbidden file pattern detected: $pattern"
		echo "Please remove secrets and sensitive files before merging."
		exit 1
	fi
done

# Check diff size (warn if too many files changed)
FILES_CHANGED=$(git diff --cached --name-only | wc -l)

if [ "$FILES_CHANGED" -gt 20 ]; then
	echo "Warning: Large diff detected ($FILES_CHANGED files changed)"
	echo "Consider breaking this into smaller changes for easier review."
	echo ""
	echo "Diff summary:"
	git diff --cached --stat
	echo ""
	# Don't exit on warning, just inform
fi

# Check that all AES phases are complete for current ticket
CURRENT_TICKET=$(grep "current_ticket:" aes/kanban.md | awk '{print $2}' | head -1)
if [ -z "$CURRENT_TICKET" ]; then
	echo "Error: No current_ticket found in aes/kanban.md"
	echo "Add 'current_ticket: TXXX' to the kanban frontmatter."
	exit 1
fi

# Check that plan, build, verify, review, learn are all done
PHASES=("plan" "build" "verify" "review" "learn")
for phase in "${PHASES[@]}"; do
	PHASE_FILE="aes/tickets/${CURRENT_TICKET}-${phase}.md"
	if [ -f "$PHASE_FILE" ]; then
		# Check if phase is marked as done
		if ! grep -q "status: done" "$PHASE_FILE"; then
			echo "Error: Phase '$phase' not completed for ticket $CURRENT_TICKET"
			echo "Please complete all phases before merging."
			exit 1
		fi
	else
		echo "Warning: Phase file not found: $PHASE_FILE"
		# This might be okay for some phases, but let's warn
	fi
done

echo "Pre-merge checks passed."
exit 0
