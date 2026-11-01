---
# Decision record — produced by /aes-project-manager.
#
# WHY THIS FILE EXISTS: a manager that answers in prose produces nothing. It
# was right for one session, contradicted in the next, and left no trace that
# the next session could inherit. This is the trace. It is written BEFORE the
# answer is spoken — if the session dies, this file is what remains.
#
# The frontmatter is MACHINE-READ by scripts/pm-decision-stats.py, which
# computes the only number that matters: decisions changed per question
# answered. A record that is not in that format is invisible to the
# measurement, and therefore does not count.
#
# VERDICT VOCABULARY is the adversarial-gate contract, not invented here:
#   SUPORTADA       -> a falsifier exists, was run, and did not refute
#   NÃO-VERIFICÁVEL -> the experiment that would settle it is named below
#   NÃO-SUPORTADA   -> the premise was false; the evidence is below
id: D000
date: YYYY-MM-DD
# `type` is REQUIRED by the OKF conformance gate (validate), which checks every
# markdown file under aes/ for frontmatter. Omitting it fails the build. Use
# `finding` for NÃO-SUPORTADA, `meta` otherwise.
type: finding
verdict: SUPORTADA
outcome: medido
question: >
  The question as actually asked, verbatim. Do not improve it. If the question
  embeds a false premise, keep the premise here — the correction belongs in the
  body, not silently in the question.
decision_changed: false
falsifier: >
  The exact command that could refute the verdict above. Not a judgement, not a
  description of a judgement. If you cannot write a command here, the verdict is
  NÃO-VERIFICÁVEL and this field is "n/a".
falsifier_exit: 0
falsifier_output: >
  The command's output, verbatim and trimmed. Not paraphrased. A reader must be
  able to re-run the command and get this text without editing it.
ticket: ''
---

# D000 — <short title>

## The question

<verbatim. If the premise is false, say so here rather than answering around it.>

## The verdict

`<SUPORTADA | NÃO-VERIFICÁVEL | NÃO-SUPORTADA>` — and the obligation that
verdict carries.

### If SUPORTADA

The falsifier, and what it did:

```
<command>
<output>
```

State plainly what this command **cannot** establish. A verdict from a command
is always narrower than the question that was asked, and the difference is where
the next mistake lives.

### If NÃO-VERIFICÁVEL

The experiment that would close it:

- **What to measure:**
- **On which artifact:**
- **What result would mean SUPORTADA:**
- **What result would mean NÃO-SUPORTADA:**
- **Cost, if known:**
- **Ticket opened:** (`produces: []`)

Stating what each possible result would *mean* is what turns an unknown into a
question. Without it, the unknown is a shrug with a ticket number.

### If NÃO-SUPORTADA

The refuting evidence:

```
<command>
<output>
```

The original false claim is **not** deleted or rewritten. The correction sits
beside it, dated. T332 is the reference: four corrections, none of which erased
the sentence they corrected.

## The substrate, if it was consulted

Was the fly-brain run? If yes, what did it say — and which of its three
permitted statements was it? (`something moved` / `nothing moved` / `the two
disagree`)

If the fly-brain is the **only** support for the verdict below, the verdict is
wrong. T330: it is a receiver. A verdict resting on its agreement is a verdict
about our encoder.

## What this cost, and what it changed

- **Cost to establish:**
- **Decision changed:** yes / no — and if no, say so. A record that changed
  nothing is still worth keeping; a record that claims to have changed something
  when it did not is the failure this whole design exists to prevent.

## What I did not establish

The blind spot, stated by the manager, in the manager's own voice, unprompted.
