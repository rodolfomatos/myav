---
template: human-validation-script
version: 1.0
created: 'YYYY-MM-DD'
requires:
  - docs/PEER_REVIEW.md
  - scripts/finding-to-ticket.sh
produces:
  - aes/peer-reviews/<CANDIDATE-ID>/human-output.md
blocked_by: ''
---

# Human Validation Script — <CANDIDATE ID>

**Executed by:** <name, NOT the maintainer>
**Date:** YYYY-MM-DD
**Clean clone:** <repo URL> @ <commit>

## Instructions

Execute each task below on a CLEAN CLONE of the candidate repository.
You have not seen this candidate before. Do not ask the maintainer for help.
Record the output or failure for each task.

## Tasks

### Task 1: Gate check
```
git clone <URL> /tmp/review-<CANDIDATE-ID>
cd /tmp/review-<CANDIDATE-ID>
make setup && make check
```
Expected: `ALL QUALITY GATES PASSED`
Actual: <record output>

### Task 2: Debt sanity
```
make debt
```
Expected: fatigue rate < 5%
Actual: <record output>

### Task 3: Claim spot-check
Open `paper/claims.md`. Find claim <C01>. Verify the evidence it cites exists at the cited path.
Expected: Evidence exists and supports the claim.
Actual: <yes/no, and why>

### Task 4: Blind-spot search
Spend 5 minutes exploring the candidate artifact. Do not look at the findings yet.
What looks suspicious to you? Record one thing that might be wrong.
Expected: <whatever you find — or "nothing looks wrong">
Actual: <your finding>

### Task 5: Finding validation
Take the first BLOCKER finding from the submitted reviews. Attempt to reproduce its evidence.
Finding: <finding ID>
Evidence: <evidence from finding>
Can you reproduce it? Yes/No
Actual: <record attempt details>

## Verdict

<!-- Executor: check the box that applies -->
- [ ] All tasks passed — no new issues found
- [ ] Tasks passed, blind-spot search found an issue — record above
- [ ] Task failed — <which task, what happened>

**Human verdict:** <recommend ACCEPT / MINOR-REVISIONS / MAJOR-REVISIONS / REJECT>
