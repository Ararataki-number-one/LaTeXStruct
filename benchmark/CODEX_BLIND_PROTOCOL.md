# Codex blind structure protocol

This protocol is for an isolated prediction or review pass over a frozen
LaTeXStruct packet.  It is deliberately independent of the gold labels and of
the production safety gate.

## Isolation

- Read only the assigned packet JSON, this protocol, and (for a review pass)
  the assigned predictor's frozen JSON.
- Do not open files whose names contain `gold`, `validation`, `score`,
  `prediction` from another pass, or the fixture builder/source corpus.
- Answer every assigned unit exactly once.  Do not add an unknown ID and do
  not omit or duplicate an ID.

## Output

Write a top-level JSON array.  Every record has exactly these semantic fields:

```json
{
  "id": "packet unit id",
  "action": "preserve | wrap | move-boundary | manual",
  "env": "",
  "start_block": 0,
  "end_block": 0,
  "reason": "brief source-based reason",
  "confidence": 0.0
}
```

`env` is a packet-allowed environment for `wrap` and `move-boundary`, and is
the empty string for `preserve` and `manual`.  `start_block` must always equal
the unit's `focus_anchor`.  For `preserve` and `manual`, `end_block` also equals
the focus.  Block IDs are JSON integers, not strings.

## Classification

- `preserve`: the focus is ordinary narrative/reference text or is already
  correctly inside a structured environment.
- `wrap`: the focus is a genuine bare theorem/lemma/definition/example/etc. or
  proof and its complete atomic range and environment type are supported by
  the visible text.
- `move-boundary`: an existing environment has a source-visible, mechanically
  provable boundary defect and the target block is unambiguous.
- `manual`: structure is plausible but the type or complete boundary is not
  machine-verifiable from the supplied blocks.  Manual is not a synonym for a
  low-effort preserve decision.

Classify only the focus.  A nearby title, citation such as “Theorem 2 shows…”,
or a theorem-looking word inside an already structured environment must not be
substituted for it.  Respect each unit's `known_structured_environments`.

## Boundary audit

For every possible automatic action, inspect every block from the focus
through the proposed end before choosing a range.

- A sentence ending, a blank line, or a grammatically complete first paragraph
  is not by itself a theorem boundary.
- When a reliable next section or structured theorem/proof begins, explicitly
  audit every nonempty block before that successor.  If all are continuations
  of the focused item, end at the last such block.  Phrases such as “The
  collection …” and “It is worth mentioning …” can introduce a continuation;
  they are not by themselves evidence that a block is outside.
- If any pre-successor block is separate discussion, or its ownership is
  genuinely uncertain, use `manual`; do not swallow it and do not silently
  truncate before it.
- A proof may end at a true terminal `\\qed`/`\\qedhere`, standalone QED
  symbol, or an unambiguous terminal completion sentence.  An operator
  `\\square`, “proof of Claim …”, a conditional phrase, or ordinary prose is
  not a terminal marker.
- Without a hard proof ending or a reliable structural successor, a
  multi-block proof is `manual`.  Do not invent a stop from a topic shift.
- Never cross a displayed formula, box, list, or nested environment closer.
  Include the whole atomic construct or choose `manual`.

## Independent review pass

Re-read the packet before looking at the frozen initial answer.  Then audit the
initial action, environment, and both block boundaries.  For a proposed
theorem/proof range, account for every block after its current end and before
the next reliable successor as `inside`, `outside`, or `uncertain` in your own
reasoning.  Correct the JSON when the evidence supports a unique answer; use
`manual` when it does not.  Do not copy the initial reason as evidence.

Before saving, validate that assigned packet IDs and output IDs are identical,
unique, and in packet order, and that every field obeys the schema above.
