@@ANCHOR:prepend@@# Platform sync — 12 March

Present: Ade, Ruth, Karim, Jo (notes)

## Carry-over from last week

The migration dry run completed on the staging cluster with two failures, both in the reporting
service and both traced to the connection pool sizing rather than to the schema change.
@@ANCHOR:mid-paragraph@@ Ruth has raised the pool limit in the staging config and the second dry run is
scheduled for Thursday.

## Decisions

- Ship the schema change behind the existing feature flag, default off.
- Reporting service gets its own pool; the shared one has been a recurring cause.
@@ANCHOR:list-item@@
- Hold the customer-facing announcement until the second dry run passes.
- Karim to write up the rollback steps before Thursday, not after.

## Open questions

Nobody could say whether the nightly export depends on the old column names. Jo to check with the data
team and report back on the thread rather than waiting for next week's sync.

## Actions

| Owner | Action                                  | Due   |
|-------|-----------------------------------------|-------|
| Ruth  | Second dry run on staging               | Thu   |
| Karim | Rollback runbook                        | Wed   |
| Jo    | @@ANCHOR:table-cell|Confirm export deps@@ | Fri   |
@@ANCHOR:trailing@@
