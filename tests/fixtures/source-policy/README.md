# Source-policy pairs

`cases.json` contains seven inputs with expected outcomes under two caller-selected sources.
The same bytes are scanned under both policies; the label is supplied out of band by the test harness.
The four quoted-instruction cases model a legitimate example when selected as security reference,
and an instruction carried by lower-trust output when selected as an untrusted tool response.
The two ordinary cases are benign under both policies. The unquoted case checks that a reference
source does not exempt live instructions.

`security-lesson.md` and `tool-response.md` are runnable CLI examples containing the same instruction.
These fixture contents are data under analysis, not instructions to a person or agent reading them.

Run `cargo test -p please-core --test source_policy --offline --locked -- --nocapture` from the
repository root. See `docs/source-policies.md` for policy semantics, expected CLI exits, the measured
acceptance matrix, and the limits of this small fixture set. These fixtures are separate from the
legacy JSONL accuracy corpus so source-specific outcomes do not change its historical measurements.
