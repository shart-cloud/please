# Contract: rule preparation

**Feature**: `002-trustworthy-core`

The seam between rule sources and an executable scanner. Its whole job is to make one sentence true:
**there is no way to obtain a scanning capability from caller-supplied rules that have not been proven to
compile within their resource budget.**

Not "callers should validate first". Not "validation is recommended". No such path exists.

---

## The surface

Three ways in, and every one of them validates:

| Entry | Provenance | Compiled validation | Cost |
|---|---|---|---|
| **built-in** | `Builtin`, minted internally | not at run time — established in CI at default limits | ~4 ms cold start |
| **from source** | `Supplied` | **every rule, at construction** | proportional to the rules supplied |
| **layered** (built-in + additions + suppressions) | per rule | **the caller's rules only** | proportional to the delta |

What is **not** on the surface: any operation that validates without producing a prepared rule set, and any
operation that produces one without validating. 001 shipped the first of those (`validate_compiled`) and it was
never called — which is the whole reason this contract exists.

## Failure is whole-set

A rule set is accepted entirely or rejected entirely, and rejection names the offending rule. A half-loaded
rule set is indistinguishable from a deliberately weakened one.

| Rejection | Established by |
|---|---|
| Malformed document, unknown field, bad identity, unknown class, out-of-range severity | cheap tier, always |
| Uncompilable pattern, look-around or backreference | cheap tier, always |
| Pattern source over length | cheap tier, always |
| **Compiled program over budget** | **expensive tier, on caller rules** |
| Rule count over limit | after resolution |
| Suppression of an unknown identifier | after resolution |

The last two are post-resolution because both are properties of the resolved set rather than of any single
source.

## Validation scope, and why the exceptions are exceptions

**Delta only.** Layering validates the caller's rules, not the union. The built-in half is already known good,
so validating it again would make adding one rule cost what validating eighty costs — which is the difference
between a usable `--rules` flag and one nobody passes twice.

**Disabled rules are validated.** They will never match, so this looks like waste. But `enabled` is a field in
a file: flipping it to `true` would turn a validated rule set into an unvalidated one *with no construction
occurring*, and validation state would go stale in silence. Validating everything present keeps the guarantee
true regardless of later enable/disable.

**Suppression validates nothing compiled.** Removing rules cannot introduce a resource problem. Suppressing an
unknown identifier is still an error, because the usual cause is a typo and a typo that quietly leaves a rule
enabled defeats the point of disabling it.

**Tightened limits revalidate everything.** A validation record is only meaningful against stated limits. If a
caller supplies limits stricter than the record's, the record does not apply — including the built-in's CI
record. Rare path, and stating it is what stops "validated" from being decoration.

## Provenance is a value, not a claim

Reading provenance is public. Minting the built-in variant is not: it is reachable only from inside
preparation, so a caller cannot obtain trusted treatment by any route — including naming their rule set
`please.builtin`, since the name is content and provenance is not derived from content.

This is enforced by the compiler. A public enum could not do it, because in Rust a public enum's variants are
publicly constructible and there is no way to make one private.

## Compiled work is retained

Proving a pattern safe compiles it. That compiled form is **kept** and becomes the executable matching state, so
no rule is compiled twice.

| | Validated at | Compiled | First scan |
|---|---|---|---|
| Built-in | CI | lazily, on first literal hit | cold start unaffected |
| Caller-supplied | construction | retained from validation | already warm |

The asymmetry is the design, not an inconsistency: it is what keeps a ~25 ms cold-start budget while still
paying the ~44 ms cost of proving untrusted rules safe — once, when the user asked for them.

## Identity covers trust

A prepared rule set's identity covers content **and** provenance **and** validation state. Two sets with
identical rules but different trust origins are distinguishable, so a verdict's rule-set field can tell an
auditor whether caller rules were involved.

## The CI check this rests on

The built-in fast path is sound only because something proves the embedded rule set validates at default
limits. **That check does not exist yet** — in 001 the expensive tier was never invoked by anything, including
on the built-in set. It is part of this feature, it is the cheapest item in it, and without it the fast path's
safety rests on nothing.
