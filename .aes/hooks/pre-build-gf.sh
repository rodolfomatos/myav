#!/bin/bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# hooks/pre-build-gf.sh — Premise Propagator
#
# Reads premise graph (DOT or JSON v2), verifies premises against reality,
# cascades failures along DEPENDS_ON edges, blocks build if critical
# premises are falsified.
#
# Three modes (automatic):
#   1. Python engine (preferred) — uses lib/premise-engine/premise_engine.py
#   2. Bash engine (fallback) — original DOT-only implementation
#
# Triggered by: pre-build hook (before any build step)
# Config:       PREMISE_GATE_LEVEL={critical|all|strict}
#               PREMISE_ENGINE=python|bash  (default: auto-detect)
#               Default: critical — FOUNDATIONAL + high-impact ASSUMPTION → exit 1
# ──────────────────────────────────────────────────────────────────────────────

PREMISES_DIR="aes/premises"
GATE_LEVEL="${PREMISE_GATE_LEVEL:-critical}"
TICKET_ID="${1:-}"
PREMISE_ENGINE="${PREMISE_ENGINE:-auto}"

ENGINE_PY="$(cd "$(dirname "$0")/.." && pwd)/lib/premise-engine/premise_engine.py"

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}PASS${NC} $1"; }
fail() { echo -e "  ${RED}FAIL${NC} $1"; }
warn() { echo -e "  ${YELLOW}WARN${NC} $1"; }
info() { echo -e "  ${CYAN}INFO${NC} $1"; }

# ── Python Engine (preferred) ──────────────────────────────────────────────────

try_python_engine() {
	local graph_file="$1"

	if [ "$PREMISE_ENGINE" = "bash" ]; then
		return 1
	fi

	if [ ! -f "$ENGINE_PY" ]; then
		[ "$PREMISE_ENGINE" = "python" ] && warn "Python engine requested but not found at ${ENGINE_PY}"
		return 1
	fi

	if ! command -v python3 &>/dev/null; then
		[ "$PREMISE_ENGINE" = "python" ] && warn "Python engine requested but python3 not available"
		return 1
	fi

	local py_fmt="auto"
	case "${graph_file}" in
	*.json) py_fmt="json" ;;
	*.dot) py_fmt="dot" ;;
	esac

	echo ""
	echo "═══════════════════════════════════════════════════════════════"
	echo "  PREMISE PROPAGATOR (Python v2 engine)"
	echo "  Graph: ${graph_file}"
	echo "  Gate level: ${GATE_LEVEL}"
	echo "═══════════════════════════════════════════════════════════════"

	local report
	report=$(python3 "$ENGINE_PY" "$graph_file" \
		--gate-level "$GATE_LEVEL" \
		--format "$py_fmt" \
		--output text 2>&1) || true

	echo "$report"

	# Also get JSON verdict for deterministic parsing
	local verdict
	verdict=$(python3 "$ENGINE_PY" "$graph_file" \
		--gate-level "$GATE_LEVEL" \
		--format "$py_fmt" \
		--output json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['gate_verdict'])" 2>/dev/null) || verdict="ERROR"

	echo ""
	case "$verdict" in
	BLOCKED)
		echo "GATE: BLOCKED — premises falsified at current gate level"
		exit 1
		;;
	PASS_WITH_WARNINGS)
		echo "GATE: PASS with warnings (non-critical premises falsified)"
		exit 0
		;;
	PASS)
		echo "GATE: PASS — all premises verified against reality"
		exit 0
		;;
	*)
		echo "GATE: ERROR — Python engine returned unexpected verdict: ${verdict}"
		exit 1
		;;
	esac
}

# ── DOT Parser ────────────────────────────────────────────────────────────────
# Populates globals: NODE_TYPES, NODE_LABELS, NODE_VERIFY, ADJ, EDGE_LABELS, NODE_ORDER

declare -gA NODE_TYPES NODE_LABELS NODE_VERIFY ADJ EDGE_LABELS
declare -ga NODE_ORDER

parse_dot() {
	local dot_file="$1"

	# Reset
	NODE_TYPES=()
	NODE_LABELS=()
	NODE_VERIFY=()
	ADJ=()
	EDGE_LABELS=()
	NODE_ORDER=()

	# Flatten DOT: join continuation lines by replacing newlines within
	# statements, then split on semicolons so each def is on one line
	local flat
	flat=$(tr -d '\n' <"$dot_file" | tr ';' '\n')

	# Parse node definitions: "id" [attr, type=TYPE, verify="val", ...]
	while IFS= read -r line; do
		line="${line#"${line%%[![:space:]]*}"}" # trim leading space
		[ -z "$line" ] && continue

		# Skip edge definitions (contain ->)
		[[ "$line" == *"->"* ]] && continue

		if ! echo "$line" | grep -q '"[^"]*"\s*\['; then
			continue
		fi

		local id=""
		id=$(echo "$line" | sed -n 's/^"\([^"]*\)".*$/\1/p')
		[ -z "$id" ] && continue

		local dtype="" dlabel="" dverify=""

		if echo "$line" | grep -q 'type='; then
			dtype=$(echo "$line" | grep -oP 'type=\w+' | head -1)
			dtype=${dtype#type=}
		fi

		if echo "$line" | grep -q 'label="'; then
			dlabel=$(echo "$line" | grep -oP 'label="[^"]*"' | head -1)
			dlabel=${dlabel#label=\"}
			dlabel=${dlabel%\"}
		fi

		if echo "$line" | grep -q 'verify="'; then
			dverify=$(echo "$line" | grep -oP 'verify="[^"]*"' | head -1)
			dverify=${dverify#verify=\"}
			dverify=${dverify%\"}
		fi

		NODE_TYPES["$id"]="$dtype"
		NODE_LABELS["$id"]="$dlabel"
		NODE_VERIFY["$id"]="$dverify"
		NODE_ORDER+=("$id")
	done < <(echo "$flat" | grep -oP '"[^"]+"\s*\[[^]]*\]' | grep 'type=' 2>/dev/null || true)

	# Parse edge definitions: "src" -> "dst" [label=TYPE]
	while IFS= read -r line; do
		local src="" dst="" rel=""

		src=$(echo "$line" | sed -n 's/^"\([^"]*\)".*$/\1/p')
		dst=$(echo "$line" | sed -n 's/.*->\s*"\([^"]*\)".*$/\1/p')
		[ -z "$src" ] || [ -z "$dst" ] && continue

		if echo "$line" | grep -q 'label='; then
			rel=$(echo "$line" | grep -oP 'label=\w+' | head -1)
			rel=${rel#label=}
		fi

		ADJ["$src"]="${ADJ[$src]:-} $dst"
		EDGE_LABELS["${src}|${dst}"]="$rel"
	done < <(echo "$flat" | grep -oP '"[^"]+"\s*->\s*"[^"]+"' 2>/dev/null || true)
}

# ── Verification ──────────────────────────────────────────────────────────────

verify_premise() {
	local id="$1"
	local verify_cmd="${NODE_VERIFY[$id]:-}"

	[ -z "$verify_cmd" ] && return 0
	[ "$verify_cmd" = "manual" ] && return 0

	case "$verify_cmd" in
	file:*)
		local path="${verify_cmd#file:}"
		[ -f "$path" ] || [ -d "$path" ]
		return $?
		;;
	cmd:*)
		local cmd="${verify_cmd#cmd:}"
		eval "$cmd" >/dev/null 2>&1
		return $?
		;;
	env:*)
		local var="${verify_cmd#env:}"
		[ -n "${!var:-}" ]
		return $?
		;;
	git:clean)
		git diff --quiet 2>/dev/null && git diff --cached --quiet 2>/dev/null
		return $?
		;;
	git:branch=*)
		local expected="${verify_cmd#git:branch=}"
		[ "$(git branch --show-current 2>/dev/null)" = "$expected" ]
		return $?
		;;
	port:*)
		local port="${verify_cmd#port:}"
		ss -tlnp 2>/dev/null | grep -q ":$port " ||
			netstat -tlnp 2>/dev/null | grep -q ":$port "
		return $?
		;;
	url:*)
		local url="${verify_cmd#url:}"
		curl -sf -o /dev/null "$url" 2>/dev/null
		return $?
		;;
	*)
		warn "Unknown verify type for [$id]: ${verify_cmd}"
		return 0
		;;
	esac
}

# ── Cascade (BFS) ─────────────────────────────────────────────────────────────

bfs_cascade() {
	local start_id="$1"
	local -a queue=("$start_id")
	local -A visited
	local -a result=()

	while [ ${#queue[@]} -gt 0 ]; do
		local current="${queue[0]}"
		queue=("${queue[@]:1}")

		[ -n "${visited[$current]:-}" ] && continue
		visited["$current"]=1
		result+=("$current")

		local downstream="${ADJ[$current]:-}"
		for dep in $downstream; do
			[ -z "${visited[$dep]:-}" ] && queue+=("$dep")
		done
	done

	echo "${result[@]}"
}

# ── Gate Logic ────────────────────────────────────────────────────────────────

should_block() {
	local node_id="$1"
	local typ="${NODE_TYPES[$node_id]:-UNKNOWN}"

	case "$GATE_LEVEL" in
	critical)
		[ "$typ" = "FOUNDATIONAL" ] && return 0
		[ "$typ" = "ASSUMPTION" ] && return 0
		return 1
		;;
	all)
		[ "$typ" = "FOUNDATIONAL" ] && return 0
		[ "$typ" = "ASSUMPTION" ] && return 0
		[ "$typ" = "CONSTRAINT" ] && return 0
		[ "$typ" = "DERIVED" ] && return 0
		return 1
		;;
	strict)
		return 0
		;;
	custom)
		local custom_file=".aes/config.mk"
		if [ -f "$custom_file" ]; then
			local block_types
			block_types=$(grep "^PREMISE_BLOCK_TYPES=" "$custom_file" | cut -d= -f2)
			if [ -n "$block_types" ]; then
				for bt in $block_types; do
					[ "$typ" = "$bt" ] && return 0
				done
			fi
		fi
		return 1
		;;
	*)
		return 1
		;;
	esac
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
	local graph_file=""

	if [ -n "$TICKET_ID" ]; then
		graph_file="${PREMISES_DIR}/${TICKET_ID}-graph.dot"
	else
		if [ -f "aes/kanban.md" ]; then
			TICKET_ID=$(grep "current_ticket:" aes/kanban.md 2>/dev/null | awk '{print $2}' | head -1 || true)
			[ -n "$TICKET_ID" ] && graph_file="${PREMISES_DIR}/${TICKET_ID}-graph.dot"
		fi
	fi

	if [ -z "${graph_file:-}" ] || [ ! -f "${graph_file:-}" ]; then
		if [ -f "${PREMISES_DIR}/project-graph.dot" ]; then
			graph_file="${PREMISES_DIR}/project-graph.dot"
			echo "No ticket graph found. Using project-level graph."
		else
			echo "Premise propagation: SKIPPED (no graph found)"
			exit 0
		fi
	fi

	if [ ! -f "$graph_file" ]; then
		echo "Premise propagation: SKIPPED (${graph_file} not found)"
		exit 0
	fi

	# Try Python engine first
	if [ "$PREMISE_ENGINE" != "bash" ] && [ -f "$ENGINE_PY" ]; then
		try_python_engine "$graph_file"
		# If Python engine didn't exit, fall through to Bash
	fi

	parse_dot "$graph_file"

	if [ ${#NODE_ORDER[@]} -eq 0 ]; then
		echo "Premise propagation: No premises found in ${graph_file}"
		exit 0
	fi

	echo ""
	echo "═══════════════════════════════════════════════════════════════"
	echo "  PREMISE PROPAGATOR — Verifying premises against reality"
	echo "  Graph: ${graph_file}"
	echo "  Gate level: ${GATE_LEVEL}"
	echo "═══════════════════════════════════════════════════════════════"
	echo ""

	# Verify each premise
	local -a failed_nodes=()

	for n in "${NODE_ORDER[@]}"; do
		local lbl="${NODE_LABELS[$n]:-$n}"
		local typ="${NODE_TYPES[$n]:-UNKNOWN}"
		local vrfy="${NODE_VERIFY[$n]:-}"

		if [ -z "$vrfy" ]; then
			continue
		fi

		if [ "$vrfy" = "manual" ]; then
			echo "  [?] ${lbl} (${typ}) — requires human judgment"
			continue
		fi

		if verify_premise "$n"; then
			pass "${lbl} (${typ})"
		else
			fail "${lbl} (${typ})"
			failed_nodes+=("$n")
		fi
	done

	# ── Inline propagation report ──────────────────────────────────────────
	local -A in_cascade
	local -a cascade_nodes=()

	for n in "${failed_nodes[@]}"; do
		local -a affected
		mapfile -t affected < <(bfs_cascade "$n")
		for a in "${affected[@]}"; do
			if [ -z "${in_cascade[$a]:-}" ]; then
				in_cascade["$a"]=1
				cascade_nodes+=("$a")
			fi
		done
	done

	if [ ${#failed_nodes[@]} -gt 0 ]; then
		echo ""
		echo "╔══════════════════════════════════════════════════════════════╗"
		echo "║           Premise Propagation Report                       ║"
		echo "╚══════════════════════════════════════════════════════════════╝"
		echo ""

		# Direct failures
		echo "Direct Failures:"
		echo "────────────────"
		for n in "${failed_nodes[@]}"; do
			local lbl="${NODE_LABELS[$n]:-$n}"
			local typ="${NODE_TYPES[$n]:-UNKNOWN}"
			local vrfy="${NODE_VERIFY[$n]:-none}"
			fail "$lbl"
			info "  Type: ${typ} | Verify: ${vrfy}"
		done

		# Cascade
		echo ""
		echo "Cascade (transitively affected):"
		echo "─────────────────────────────────"
		local cascade_count=0
		for n in "${cascade_nodes[@]}"; do
			local lbl="${NODE_LABELS[$n]:-$n}"
			local typ="${NODE_TYPES[$n]:-UNKNOWN}"
			local is_direct=0
			for f in "${failed_nodes[@]}"; do
				[ "$f" = "$n" ] && is_direct=1
			done
			[ "$is_direct" = "1" ] && continue
			info "${lbl} (${typ})"
			cascade_count=$((cascade_count + 1))
		done
		if [ "$cascade_count" = "0" ]; then
			info "(no indirect cascade)"
		fi

		# Non-affected
		echo ""
		echo "Non-affected (safe to proceed):"
		echo "─────────────────────────────────"
		local safe_count=0
		for n in "${NODE_ORDER[@]}"; do
			if [ -z "${in_cascade[$n]:-}" ]; then
				local lbl="${NODE_LABELS[$n]:-$n}"
				info "${lbl}"
				safe_count=$((safe_count + 1))
			fi
		done
		if [ "$safe_count" = "0" ]; then
			info "(none — all premises in cascade)"
		fi
		echo ""
	fi

	# ── Gate decision ─────────────────────────────────────────────────────
	local block=0

	for n in "${cascade_nodes[@]}"; do
		if should_block "$n"; then
			local lbl="${NODE_LABELS[$n]:-$n}"
			local typ="${NODE_TYPES[$n]:-UNKNOWN}"
			block=1
			warn "BLOCKING: ${lbl} (${typ})"
		fi
	done

	# Additional DEPENDS_ON check for DERIVED/CONSTRAINT in critical mode
	if [ "$GATE_LEVEL" = "critical" ] && [ "$block" = "0" ] && [ ${#failed_nodes[@]} -gt 0 ]; then
		for n in "${cascade_nodes[@]}"; do
			local typ="${NODE_TYPES[$n]:-UNKNOWN}"
			if [ "$typ" = "DERIVED" ] || [ "$typ" = "CONSTRAINT" ]; then
				for f in "${failed_nodes[@]}"; do
					local rel="${EDGE_LABELS[${f} | ${n}]:-}"
					if [ "$rel" = "DEPENDS_ON" ]; then
						block=1
						local lbl="${NODE_LABELS[$n]:-$n}"
						warn "BLOCKING: ${lbl} (${typ}) — DEPENDS_ON falsified premise"
						break
					fi
				done
			fi
		done
	fi

	echo ""
	if [ "$block" = "1" ]; then
		echo "GATE: BLOCKED — premises falsified at current gate level"
		echo "Fix the failed premises or set PREMISE_GATE_LEVEL to a lower"
		echo "threshold to proceed."
		exit 1
	fi
	if [ ${#failed_nodes[@]} -gt 0 ]; then
		echo "GATE: PASS with warnings (non-critical premises falsified)"
		exit 0
	fi
	echo "GATE: PASS — all premises verified against reality"
	exit 0
}

main "$@"
