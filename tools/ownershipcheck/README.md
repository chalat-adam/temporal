# ownershipcheck

A static analyzer that flags a **borrowed** (possibly shared) map or slice being
embedded by reference into a **protobuf message that crosses a package boundary**
(e.g. a gRPC response). Such a value can be mutated by its retained alias while
gRPC marshals the response *outside any lock*, producing
`concurrent map iteration and map write` crashes. See CDS-2866 and
temporalio/temporal#10706 / #10707.

## What it reports

Inside an exported function, embedding a map/slice into a `proto.Message` literal
when that value is **borrowed** — i.e. read out of the shared, leased component
(the method receiver), directly or through an accessor/getter:

```go
// flagged:
return &schedulepb.DescribeScheduleResponse{
    Memo: &commonpb.Memo{Fields: visibility.CustomMemo(ctx)},
}
// fixed:
return &schedulepb.DescribeScheduleResponse{
    Memo: &commonpb.Memo{Fields: maps.Clone(visibility.CustomMemo(ctx))},
}
```

Both embed forms are covered: a composite-literal field (`&Memo{Fields: x}`) and a
field assignment (`resp.Memo.Fields = x`).

It only flags a proto that **escapes** the function — returned, or assigned into a
returned proto. A proto that is deep-cloned in place (`return CloneProto(tmp)`),
marshaled synchronously (`return p.Marshal()`), or read for a local computation
never reaches an out-of-lock marshal and is not flagged. It is also quiet on the
common-and-safe case: a value produced locally (`make`/literal/clone) with no
retained alias is the sole owner. A value rooted at a **parameter** or a **package
global** is treated as owned. The hazard is specifically shared *instance* state.

## Running it

Standalone (vet-style), as a dependency-aware single checker:

```
go run ./cmd/tools/ownershipcheck ./...
go vet -vettool=$(go build -o /tmp/ownershipcheck ./cmd/tools/ownershipcheck && echo /tmp/ownershipcheck) ./...
```

It uses `go/analysis` Facts, so cross-package inference is build-cache friendly
and runs package-at-a-time.

## Directives

- `//ownership:result owned` / `//ownership:result borrowed` — on a function
  declaration, override inference for that function's result. `owned` suppresses
  (e.g. an accessor that returns an immutable snapshot, or clones internally in a
  way inference can't see). `borrowed` forces a borrowed result (e.g. the real
  source is reached through an interface). The override is exported as a Fact, so
  it applies cross-package.

- `//ownership:ignore <reason>` — on the embed line (or the line directly above),
  suppress a single finding. A **reason is required**, so suppressions are
  reviewable rather than silent.

  ```go
  Fields: c.memo, //ownership:ignore immutable after init, never mutated
  ```

- `//ownership:frozen` — on a **struct field** or a **method**, mark its data
  immutable. Frozen data is safe to embed even when read off the receiver, and any
  write to it — directly or through an alias, *even on a dead branch* — is flagged
  with the path back to the source. The fact is exported cross-package.

  ```go
  type Component struct {
      //ownership:frozen
      cfg map[string]*commonpb.Payload   // never written after construction
  }

  //ownership:frozen
  func (c *Component) Config() map[string]*commonpb.Payload { return c.cfg }
  ```

  Enforcement is intraprocedural (taint is followed within a function); writes
  reachable only through other packages, interfaces, or reflection aren't caught.

## Rollout

It runs as a standalone vet-style tool — the `ownership-check` job in
`.github/workflows/run-tests.yml` invokes `go run ./cmd/tools/ownershipcheck ./...`.

1. **Warn-only** first: the CI job uses `continue-on-error`, so findings show in the
   log without blocking. Triage the initial hit list (the CDS-2866-style audit) —
   annotate the legitimate ones (`//ownership:ignore <reason>`, `//ownership:frozen`),
   fix the real ones.
2. **Gate** once the backlog is handled: drop `continue-on-error` and add
   `ownership-check` to the `test-status` job's `needs`.

(There is no golangci-lint integration; the standalone tool and its
`//ownership:ignore` hatch cover suppression directly.)

## Scope (what it does NOT do)

- No lock/region or concurrency analysis; "borrowed" is approximated structurally.
- Sinks are **assignments** (composite literals + field assignments). Setters
  (`resp.SetX(v)`) are not detected — that needs cross-call param→field modeling.
- Escape is intra-procedural: a borrowed proto passed as an argument to another
  package's function (which may marshal it) is not currently flagged.
- Spatial axis only (value crosses a package boundary). The temporal axis
  (same-package goroutine/closure capture) is out of scope.
- Not sound: accepts some false positives (annotate them) and some false negatives
  (e.g. a mutable *package-global* map, or borrowing reached only through
  reflection/`any`). Targets the CDS-2866 class, not all aliasing bugs.

See `../../../plan.md` for the full design and milestone history.
