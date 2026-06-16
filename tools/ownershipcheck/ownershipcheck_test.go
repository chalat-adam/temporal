package ownershipcheck_test

import (
	"testing"

	"go.temporal.io/server/tools/ownershipcheck"
	"golang.org/x/tools/go/analysis/analysistest"
)

// TestDirectEmbed covers the intra-procedural sink: a map/slice read directly
// from the receiver and embedded into a returned proto, plus the owned negatives.
func TestDirectEmbed(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), ownershipcheck.Analyzer,
		"directembed", // positive: must report
		"freshsend",   // negative: freshly made, never published
		"cloned",      // negative: maps.Clone sanitizes
	)
}

// TestAccessorInference covers return-field inference exported as facts, including
// cross-package resolution. Mirrors the scheduler (#10706) and nexus (#10707) leaks.
func TestAccessorInference(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), ownershipcheck.Analyzer,
		"samepackageaccessor",  // positive: same-package accessor inference
		"accessorlib",          // dependency: exports borrowed/owned result facts
		"crosspackageaccessor", // positive: cross-package facts
	)
}

// TestProjection covers provenance-aware projection: a getter on an owned receiver
// (parameter) stays silent, while a value rooted at the shared receiver — even
// through generics, comma-ok type assertions, and multi-level delegation — is
// flagged. Mirrors the chasm.Field[T].Get scheduler case.
func TestProjection(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), ownershipcheck.Analyzer,
		"genericfield", // positive: receiver-rooted leak through generic delegation
		"getterparam",  // negative: getter on a parameter receiver stays silent
		"subslice",     // positive: re-slice of a borrowed slice
	)
}

// TestDirectives covers the //ownership: directives: result annotations (override
// inference both ways) and the //ownership:ignore hatch (reason required).
func TestDirectives(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), ownershipcheck.Analyzer,
		"annotations",     // //ownership:result owned suppresses; borrowed forces
		"ignoredirective", // //ownership:ignore <reason> suppresses; bare does not
	)
}

// TestEscape covers escape verification (only protos that actually escape the
// function are sinks) and the field-assignment sink (resp.Field = borrowed).
func TestEscape(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), ownershipcheck.Analyzer,
		"escapeclone", // negative: build-then-clone, alias never escapes
		"escapelocal", // negative: temp proto consumed locally, never returned
		"fieldassign", // positive: resp.Field = borrowed on a returned proto
		"outputparam", // positive: borrowed written into a proto-pointer parameter
	)
}

// TestFrozen covers //ownership:frozen on fields and methods: the data is safe to
// embed even when read off the receiver, and writes to it (directly or via an
// alias) are flagged with the path back to the source.
func TestFrozen(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), ownershipcheck.Analyzer, "frozen")
}

// TestInterproc covers interprocedural param summaries: a borrowed value passed to
// a parameter the callee embeds into an escaping proto is flagged at the call site.
// (Frozen-through-a-mutating-callee is covered in TestFrozen.)
func TestInterproc(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), ownershipcheck.Analyzer, "builderparam")
}

// TestKnownGaps documents false-positive / false-negative cases the analyzer does
// NOT handle yet. It is skipped on purpose: these fixtures (under
// testdata/src/knowngaps) describe desired-but-unimplemented behavior and would
// fail today. See testdata/src/knowngaps/README.md and plan.md. When a gap is
// implemented, move its package into the relevant real test.
func TestKnownGaps(t *testing.T) {
	t.Skip("documents known FP/FN gaps; see testdata/src/knowngaps/README.md and plan.md")
}
