# Writing and layering rules

Rules are **data, not code** (constitution Principle III). A team that disagrees with a finding edits a TOML
file and re-runs; they do not file an issue and wait for a release.

```sh
plz scan --rules acme-rules.toml --disable-rule override.disregard_prior ./skills
```

Both flags are **repeatable**. Neither requires a rebuild of `plz`.

---

## The file

`rules/builtin.toml` is the worked reference — it is the shipped rule set, written to be read. A minimal
addition:

```toml
[ruleset]
name = "acme.internal"
version = "1.0.0"

[[rule]]
id = "boundary.acme_tool_marker"
class = "boundary"
severity = 75
literals = ["ACME-TOOL"]
pattern = '(?i)<<ACME-TOOL:[a-z_]+>>'
description = "Forged Acme internal tool-result marker. Only the tool runner emits these."
```

| Field | Required | Notes |
|---|---|---|
| `id` | yes | Namespaced, `^[a-z0-9_]+(\.[a-z0-9_]+)+$`. Also the handle for `--disable-rule` |
| `class` | yes | `override`, `boundary`, `solicitation`, `agent_directed` |
| `severity` | yes | `0..=100`. This rule's contribution before aggregation |
| `literals` | yes | At least one. See below — this is not a formality |
| `pattern` | yes | Finite-automaton syntax |
| `description` | yes | Non-empty. An unexplained finding is one nobody can act on |

`[ruleset]` needs `name` and `version`; `[bands]` is optional and defaults to the built-in table.

### Two rules that are enforced rather than encouraged

**Every rule needs at least one literal.** All literals across all rules go into one automaton, and a rule's
`pattern` is compiled only if one of its literals is present in the input. Text matching no literal costs a
single linear pass and compiles nothing — 0.1 ms instead of 44 ms. A rule with no literal loads but warns,
because it makes every scan pay for itself.

**Look-around and backreferences are not expressible.** A pattern using them fails to compile and therefore
fails to load. That is not a limitation being apologised for: it is what makes every accepted rule
linear-time, so the guarantee is structural rather than a review habit. There is no way to write a
catastrophically backtracking rule.

Patterns are also matched against **decoded** content, so a base-64 or tag-block payload is caught by the
same rule that catches it in the clear. There is no separate corpus of "encoded" rules to keep in sync.

### Two classes you cannot declare

`concealment` and `confusable` are detected in code, not by pattern. They recognise a *mechanism* rather
than a phrase — a run of tag-block characters means the same thing regardless of what it decodes to, and no
pattern could express that.

---

## Resolution order

```text
built-in default  →  additions (--rules, in argument order)  →  suppressions (--disable-rule)
```

**An addition whose `id` matches an existing rule replaces it**, and the replacement is reported on stderr:

```text
plz: warning: rule `override.disregard_prior` replaced by an addition from `acme.internal`
```

That warning is the point of the feature working the way it does. Replacing a built-in silently is how a
team disables detection without meaning to; the line above is what stands between *"we tuned a rule"* and
*"we turned one off and nobody noticed"*.

**Suppression takes effect last**, so a rule can be added by one layer and disabled by another. With
several `--rules`, later files win id collisions — order is the operator's, visible on the command line.

**The resolved set's digest covers what survived**, so a verdict's `ruleset` field describes what actually
ran rather than what was requested (SC-012). Add a rule and the digest moves; a verdict from last week stays
attributable to the rules that produced it.

A disabled rule stays in the identity while being excluded from matching — so *"we ran the built-in set with
one rule off"* is a different, distinguishable thing from *"we ran a set that never had it"*.

---

## When loading fails

`plz` **does not proceed on a partially loaded rule set** (FR-024). Every failure below is exit code **64**,
a usage error, with nothing on stdout:

```text
$ plz scan --rules bad.toml note.txt
plz: bad.toml: rule set is not valid TOML: TOML parse error at line 1, column 6

$ plz scan --rules overcooked.toml note.txt
plz: overcooked.toml: rule `acme.overcooked`: severity 999 outside 0..=100

$ plz scan --disable-rule override.no_such_rule note.txt
plz: cannot suppress unknown rule `override.no_such_rule`. This is an error rather than a
     no-op because the usual cause is a typo, and a typo that leaves a rule enabled defeats
     the point of disabling it
```

**Exit 64 and not 70.** A caller's malformed TOML is an invocation fault; `70` is reserved for the *built-in*
rule set failing to load, which is a build defect a user cannot cause and cannot fix. If you ever see 70
from a rule-set failure, that is a bug worth reporting.

The diagnostic always names the offending rule, and — because `--rules` is repeatable — the file it came
from.

### Rules are validated, not just parsed

A resource-exhausting rule is not malformed. `a{1000}{1000}{1000}` is nineteen bytes of valid syntax that
parses in microseconds and compiles to an automaton with on the order of 10⁹ states. Every caller-supplied
rule must **compile** within a stated budget before the rule set yields a scanner at all (FR-024, as amended
by 002 FR-150).

Validation is **delta only**: your addition costs what your rules cost, not what the built-in eighty cost.
Adding one rule to an eighty-rule set does not pay to re-validate the eighty.

---

## The same thing from Rust

The CLI holds no capability the library lacks (Principle V). `--rules` and `--disable-rule` are a thin
wrapper over:

```rust
let engine = Engine::builder()
    .add_ruleset(Ruleset::from_toml(&std::fs::read_to_string("acme-rules.toml")?)?)
    .disable("override.disregard_prior")
    .build()?;
```

`Ruleset::from_toml` takes **text, not a path**, deliberately: the core performs no I/O, which is what lets
the same engine run in a browser. Opening the file is the caller's job, and for `plz` that is
`crates/cli/src/target.rs`.
