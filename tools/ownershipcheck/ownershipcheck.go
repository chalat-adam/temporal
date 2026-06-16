// Package ownershipcheck is a static analyzer that flags a borrowed (possibly
// shared) map or slice being embedded by reference into a protobuf message that
// crosses a package boundary (e.g. a gRPC response). Such a value can be mutated
// by its retained alias while gRPC marshals the response outside any lock,
// producing "concurrent map iteration and map write" crashes (see CDS-2866).
//
// Cross-package inference via go/analysis Facts, with provenance-aware field
// projection. Ownership is classified per expression as one of three forms:
//
//	owned        – freshly produced here (make/literal/clone) or rooted at a
//	               parameter (optimistically owned); safe to embed.
//	viaReceiver  – borrowed, but only because it is read out of the *receiver*
//	               (the shared, long-lived component). A function with a
//	               viaReceiver result (e.g. CustomMemo doing `return v.memo`, or a
//	               generated getter doing `return x.field`) is borrowed at a call
//	               site iff the call's RECEIVER expression is borrowed there.
//	unconditional – borrowed from a package global or other always-shared source.
//
// Per-result forms are exported as a resultOwnership ObjectFact so callers in
// other packages resolve them without re-analysis. The sink check flags a
// map/slice embedded into a protobuf-message literal inside an exported function
// when its resolved form is not owned.
//
// Provenance is what stops false positives like searchAttributes.GetIndexedFields()
// on a *parameter*: the getter is viaReceiver, the receiver (a param) is owned, so
// the result is owned. The same machinery keeps o.Visibility.CustomMemo() borrowed,
// because there the receiver roots at the handler's own receiver.
//
// The //ownership:result, //ownership:ignore, and //ownership:frozen directives
// override inference and suppress findings.
package ownershipcheck

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const Doc = `flag borrowed maps/slices embedded by reference into protobuf responses

A map/slice read out of shared state (a field, or an accessor/getter that returns
an internal field by reference) and embedded into a protobuf message returned
from an exported function can be mutated by its retained alias while gRPC marshals
the response outside any lock. Clone it (maps.Clone / slices.Clone) first.`

// form is the ownership classification of an expression or function result.
type form uint8

const (
	owned         form = iota // freshly produced, rooted at a parameter, or a global
	viaReceiver               // borrowed via the receiver; resolves against the call receiver
	unconditional             // always borrowed; only produced by a //ownership:result borrowed annotation
)

// A struct field or method declared //ownership:frozen is immutable: its data is
// safe to embed even when read off the receiver (markFrozen / isFrozenField /
// isFrozenObj), and any write to it is flagged (checkFrozen) by silently tainting
// aliases and reporting the path back to the source. Writes through a callee are
// caught via parameter summaries (paramSummary.Mutated).
// TODO: conservatively flag frozen data escaping into opaque boundaries
// (interfaces, reflection, third-party) that summaries cannot see through.

func moreBorrowed(a, b form) form {
	if a > b {
		return a
	}
	return b
}

// resultOwnership is an ObjectFact attached to a *types.Func recording the
// ownership form of each result. Absence means "all results owned"; only facts
// with at least one non-owned result are exported.
type resultOwnership struct {
	Forms []form
}

func (*resultOwnership) AFact() {}

// String controls how analysistest renders the fact in // want expectations.
func (r *resultOwnership) String() string {
	n := 0
	for _, f := range r.Forms {
		if f != owned {
			n++
		}
	}
	if n == 1 && len(r.Forms) > 0 && r.Forms[0] != owned {
		return "borrowed result"
	}
	return "borrowed results"
}

// frozenFact is an ObjectFact attached to a struct field (*types.Var) or a method
// (*types.Func) declared //ownership:frozen — its data is immutable, hence safe to
// embed even when read off the receiver, and any write to it is a violation.
type frozenFact struct{}

func (*frozenFact) AFact()         {}
func (*frozenFact) String() string { return "frozen" }

// paramSummary is an ObjectFact attached to a *types.Func summarizing what it does
// to each parameter, for interprocedural reasoning at call sites:
//   - Mutated[i]: param i's data is written (directly or transitively) — passing
//     frozen data to such a param is a violation.
//   - Embedded[i]: param i (a map/slice) is embedded into a proto that escapes the
//     function — passing a borrowed value to such a param leaks it.
type paramSummary struct {
	Mutated  []bool
	Embedded []bool
}

func (*paramSummary) AFact() {}

func (s *paramSummary) String() string {
	var parts []string
	if anyBool(s.Mutated) {
		parts = append(parts, "mutates param")
	}
	if anyBool(s.Embedded) {
		parts = append(parts, "embeds param")
	}
	return strings.Join(parts, ", ")
}

func anyBool(b []bool) bool {
	for _, v := range b {
		if v {
			return true
		}
	}
	return false
}

func boolsEqual(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// defaultCloneHelpersList is the default value of the -clone-helpers flag: a
// call to one of these (pkg.Func) yields an owned value regardless of its
// arguments. Configure the whole set via the flag.
const defaultCloneHelpersList = "maps.Clone,slices.Clone,proto.Clone,proto.CloneOf,common.CloneProto"

// cloneHelpersFlag is the configured set of clone helpers (comma-separated pkg.Func).
var cloneHelpersFlag string

// parseCloneHelpers builds the clone-helper set from the -clone-helpers flag.
func parseCloneHelpers() map[string]map[string]bool {
	m := map[string]map[string]bool{}
	for _, entry := range strings.Split(cloneHelpersFlag, ",") {
		entry = strings.TrimSpace(entry)
		pkg, fn, ok := strings.Cut(entry, ".")
		if !ok || pkg == "" || fn == "" {
			continue
		}
		if m[pkg] == nil {
			m[pkg] = map[string]bool{}
		}
		m[pkg][fn] = true
	}
	return m
}

var Analyzer = &analysis.Analyzer{
	Name:      "ownershipcheck",
	Doc:       Doc,
	Run:       run,
	FactTypes: []analysis.Fact{(*resultOwnership)(nil), (*frozenFact)(nil), (*paramSummary)(nil)},
}

func init() {
	Analyzer.Flags.StringVar(&cloneHelpersFlag, "clone-helpers", defaultCloneHelpersList,
		"comma-separated clone helpers as pkg.Func that sanitize a borrowed value")
}

type checker struct {
	pass       *analysis.Pass
	local      map[*types.Func]*resultOwnership // forms inferred for funcs in this package
	proto      map[types.Type]bool              // memoized isProtoMessage results
	clone      map[string]map[string]bool       // pkg -> func -> is a clone helper
	frozenObjs map[types.Object]bool            // fields/methods declared //ownership:frozen here
	summaries  map[*types.Func]*paramSummary    // per-func parameter effect summaries
}

func run(pass *analysis.Pass) (any, error) {
	c := &checker{
		pass:       pass,
		local:      map[*types.Func]*resultOwnership{},
		proto:      map[types.Type]bool{},
		clone:      parseCloneHelpers(),
		frozenObjs: map[types.Object]bool{},
		summaries:  map[*types.Func]*paramSummary{},
	}
	c.markFrozen()  // record & export //ownership:frozen fields/methods
	c.infer()       // phase A: compute & export per-result ownership forms
	c.summarize()   // phase A2: compute & export per-param effect summaries
	c.report()      // phase B: flag borrowed embeds (incl. via embedding params)
	c.checkFrozen() // phase C: flag writes to frozen data (incl. via mutating params)
	return nil, nil
}

// markFrozen records struct fields and methods declared //ownership:frozen and
// exports the fact so importing packages see it.
func (c *checker) markFrozen() {
	mark := func(name *ast.Ident) {
		if obj := c.pass.TypesInfo.Defs[name]; obj != nil {
			c.frozenObjs[obj] = true
			c.pass.ExportObjectFact(obj, &frozenFact{})
		}
	}
	for _, file := range c.pass.Files {
		for _, d := range file.Decls {
			switch decl := d.(type) {
			case *ast.FuncDecl:
				if frozenAnnotated(decl.Doc) {
					mark(decl.Name) // frozen method: its result is immutable
				}
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue
					}
					for _, field := range st.Fields.List {
						if !frozenAnnotated(field.Doc) {
							continue
						}
						for _, name := range field.Names {
							mark(name) // frozen field
						}
					}
				}
			}
		}
	}
}

// isFrozenObj reports whether obj (a field or method) is declared //ownership:frozen.
func (c *checker) isFrozenObj(obj types.Object) bool {
	if obj == nil {
		return false
	}
	if fn, ok := obj.(*types.Func); ok {
		obj = fn.Origin()
	}
	if c.frozenObjs[obj] {
		return true
	}
	var f frozenFact
	return c.pass.ImportObjectFact(obj, &f)
}

// isFrozenField reports whether sel reads a //ownership:frozen struct field.
func (c *checker) isFrozenField(sel *ast.SelectorExpr) bool {
	v, ok := c.pass.TypesInfo.ObjectOf(sel.Sel).(*types.Var)
	return ok && v.IsField() && c.isFrozenObj(v)
}

// ---- phase C: frozen-write enforcement -------------------------------------

// frozenTaint records that a value derives from a frozen source, with the path
// from that source (rendered as analysis.RelatedInformation hops).
type frozenTaint struct {
	origin    string    // human description of the frozen source
	originPos token.Pos // where the frozen source is declared
	hops      []analysis.RelatedInformation
}

func (t *frozenTaint) related() []analysis.RelatedInformation {
	out := []analysis.RelatedInformation{{Pos: t.originPos, Message: "frozen source: " + t.origin}}
	return append(out, t.hops...)
}

// checkFrozen flags writes to frozen data anywhere (any attempt is a violation,
// dead code included), following aliases and sub-vars within each function. It is
// silent: the only annotation is at the source; the violation reports the path.
func (c *checker) checkFrozen() {
	if len(c.frozenObjs) == 0 && !c.anyImportedFrozen() {
		return // no frozen sources reachable; nothing to enforce
	}
	for _, file := range c.pass.Files {
		if f := c.pass.Fset.File(file.Pos()); f != nil && strings.HasSuffix(f.Name(), "_test.go") {
			continue
		}
		for _, d := range file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			taint := c.frozenTaintOf(fd)
			c.reportFrozenWrites(fd, taint)
		}
	}
}

// anyImportedFrozen reports whether any dependency exported a frozen fact (so a
// frozen field/method from another package may be used here).
func (c *checker) anyImportedFrozen() bool {
	for _, f := range c.pass.AllObjectFacts() {
		if _, ok := f.Fact.(*frozenFact); ok {
			return true
		}
	}
	return false
}

// frozenTaintOf computes, per local variable, whether it is tainted by a frozen
// source and the path that tainted it. Forward, source-order; def-before-use in
// Go makes a single pass sufficient.
func (c *checker) frozenTaintOf(fd *ast.FuncDecl) map[*types.Var]*frozenTaint {
	taint := map[*types.Var]*frozenTaint{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != len(as.Rhs) {
			return true
		}
		for i, lhs := range as.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok {
				continue
			}
			v, ok := c.pass.TypesInfo.ObjectOf(id).(*types.Var)
			if !ok {
				continue
			}
			if ft := c.frozenSource(as.Rhs[i], taint); ft != nil {
				hop := analysis.RelatedInformation{
					Pos:     id.Pos(),
					Message: fmt.Sprintf("frozen data aliased as %q here", id.Name),
				}
				taint[v] = &frozenTaint{origin: ft.origin, originPos: ft.originPos, hops: append(ft.hops, hop)}
			}
		}
		return true
	})
	return taint
}

// frozenSource returns taint info if expr derives from a frozen source (a frozen
// field read, a frozen method result, or a tainted variable), else nil. Projections
// (index, slice, deref, field, type-assert) inherit the base.
func (c *checker) frozenSource(expr ast.Expr, taint map[*types.Var]*frozenTaint) *frozenTaint {
	switch e := unparen(expr).(type) {
	case *ast.Ident:
		if v, ok := c.pass.TypesInfo.ObjectOf(e).(*types.Var); ok {
			return taint[v]
		}
	case *ast.SelectorExpr:
		if c.isFrozenField(e) {
			obj := c.pass.TypesInfo.ObjectOf(e.Sel)
			return &frozenTaint{origin: "field " + e.Sel.Name + " (//ownership:frozen)", originPos: obj.Pos()}
		}
		return c.frozenSource(e.X, taint)
	case *ast.IndexExpr:
		return c.frozenSource(e.X, taint)
	case *ast.SliceExpr:
		return c.frozenSource(e.X, taint)
	case *ast.StarExpr:
		return c.frozenSource(e.X, taint)
	case *ast.TypeAssertExpr:
		return c.frozenSource(e.X, taint)
	case *ast.CallExpr:
		if fn := c.calleeFunc(e); fn != nil && c.isFrozenObj(fn) {
			return &frozenTaint{origin: "result of " + fn.Name() + " (//ownership:frozen)", originPos: fn.Pos()}
		}
	}
	return nil
}

// reportFrozenWrites flags any syntactic write to frozen-tainted data.
func (c *checker) reportFrozenWrites(fd *ast.FuncDecl, taint map[*types.Var]*frozenTaint) {
	report := func(pos token.Pos, what string, ft *frozenTaint) {
		c.pass.Report(analysis.Diagnostic{
			Pos:     pos,
			Message: "frozen data mutated (" + what + "); it is declared //ownership:frozen and must not be written",
			Related: ft.related(),
		})
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range stmt.Lhs {
				base, what := writeTarget(lhs)
				if base == nil {
					continue
				}
				if ft := c.frozenSource(base, taint); ft != nil {
					report(lhs.Pos(), what, ft)
				}
			}
		case *ast.IncDecStmt:
			if base, what := writeTarget(stmt.X); base != nil {
				if ft := c.frozenSource(base, taint); ft != nil {
					report(stmt.X.Pos(), what, ft)
				}
			}
		case *ast.CallExpr:
			if name, ok := c.builtinName(stmt); ok {
				if name == "append" || name == "delete" || name == "clear" {
					if len(stmt.Args) > 0 {
						if ft := c.frozenSource(stmt.Args[0], taint); ft != nil {
							report(stmt.Args[0].Pos(), name, ft)
						}
					}
				}
				return true
			}
			// Interprocedural: frozen data passed to a parameter the callee mutates.
			callee := c.calleeFunc(stmt)
			if callee == nil {
				return true
			}
			cs := c.paramSummaryOf(callee)
			if cs == nil {
				return true
			}
			for j, arg := range stmt.Args {
				if j >= len(cs.Mutated) || !cs.Mutated[j] {
					continue
				}
				if ft := c.frozenSource(arg, taint); ft != nil {
					related := append(ft.related(), analysis.RelatedInformation{
						Pos:     callee.Pos(),
						Message: callee.Name() + " mutates this parameter",
					})
					c.pass.Report(analysis.Diagnostic{
						Pos:     arg.Pos(),
						Message: "frozen data passed to " + callee.Name() + ", which mutates it; frozen data must not be written",
						Related: related,
					})
				}
			}
		}
		return true
	})
}

// writeTarget returns the base expression a write mutates (the map/slice/struct/
// pointee), and a short description, or (nil, "") if lhs is a plain rebind.
func writeTarget(lhs ast.Expr) (ast.Expr, string) {
	switch e := unparen(lhs).(type) {
	case *ast.IndexExpr:
		return e.X, "index store" // m[k] = v
	case *ast.StarExpr:
		return e.X, "pointer store" // *p = v
	case *ast.SelectorExpr:
		return e.X, "field store" // p.f = v
	}
	return nil, ""
}

// builtinName returns the name of a builtin call (append/delete/clear/...) if the
// callee is a builtin.
func (c *checker) builtinName(call *ast.CallExpr) (string, bool) {
	id, ok := unparen(call.Fun).(*ast.Ident)
	if !ok {
		return "", false
	}
	if _, ok := c.pass.TypesInfo.ObjectOf(id).(*types.Builtin); !ok {
		return "", false
	}
	return id.Name, true
}

// fnScope is the per-function classification context.
type fnScope struct {
	c      *checker
	recv   *types.Var
	params map[*types.Var]bool
	locals map[*types.Var]form
}

func (c *checker) newScope(fd *ast.FuncDecl) *fnScope {
	s := &fnScope{c: c, params: map[*types.Var]bool{}, locals: map[*types.Var]form{}}
	if fd.Recv != nil {
		for _, f := range fd.Recv.List {
			for _, n := range f.Names {
				if v, ok := c.pass.TypesInfo.Defs[n].(*types.Var); ok {
					s.recv = v
				}
			}
		}
	}
	if fd.Type.Params != nil {
		for _, f := range fd.Type.Params.List {
			for _, n := range f.Names {
				if v, ok := c.pass.TypesInfo.Defs[n].(*types.Var); ok {
					s.params[v] = true
				}
			}
		}
	}
	s.collectLocals(fd)
	return s
}

// collectLocals classifies local variables from their defining assignments
// (flow-insensitive single pass; sufficient for the patterns we target).
func (s *fnScope) collectLocals(fd *ast.FuncDecl) {
	mark := func(lhs ast.Expr, f form) {
		if id, ok := lhs.(*ast.Ident); ok {
			if v, ok := s.c.pass.TypesInfo.ObjectOf(id).(*types.Var); ok {
				s.locals[v] = f
			}
		}
	}
	ast.Inspect(fd.Body, func(node ast.Node) bool {
		if _, ok := node.(*ast.FuncLit); ok {
			return false
		}
		as, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		if len(as.Rhs) == 1 {
			if call, ok := unparen(as.Rhs[0]).(*ast.CallExpr); ok && len(as.Lhs) >= 1 {
				for i, lhs := range as.Lhs {
					mark(lhs, s.callResultForm(call, i))
				}
				return true
			}
			// comma-ok forms: `v, ok := x.(T)` and `v, ok := m[k]` — v inherits
			// the base's ownership (same projection rule), ok is owned.
			if len(as.Lhs) == 2 {
				switch r := unparen(as.Rhs[0]).(type) {
				case *ast.TypeAssertExpr:
					mark(as.Lhs[0], s.classify(r.X))
					mark(as.Lhs[1], owned)
					return true
				case *ast.IndexExpr:
					mark(as.Lhs[0], s.classify(r.X))
					mark(as.Lhs[1], owned)
					return true
				}
			}
		}
		if len(as.Lhs) == len(as.Rhs) {
			for i, lhs := range as.Lhs {
				mark(lhs, s.classify(as.Rhs[i]))
			}
		}
		return true
	})
}

// classify returns the ownership form of an expression within this scope.
func (s *fnScope) classify(expr ast.Expr) form {
	switch e := unparen(expr).(type) {
	case *ast.Ident:
		v, ok := s.c.pass.TypesInfo.ObjectOf(e).(*types.Var)
		if !ok {
			return owned
		}
		if v == s.recv {
			return viaReceiver
		}
		if s.params[v] {
			return owned
		}
		if f, ok := s.locals[v]; ok {
			return f
		}
		// Package globals and unresolved locals are treated as owned. The
		// CDS-2866 class is shared *instance* state read off the leased
		// component (the receiver), not package-level globals (which are almost
		// always immutable, e.g. serialized tokens). This trades a rare FN
		// (mutable global map) for precision.
		return owned
	case *ast.SelectorExpr:
		if s.c.isFrozenField(e) {
			return owned // a frozen field is immutable, safe to embed
		}
		// A field selection inherits the base's ownership; a package-qualified
		// global is owned (see above).
		if _, isSel := s.c.pass.TypesInfo.Selections[e]; isSel {
			return s.classify(e.X)
		}
		return owned
	case *ast.IndexExpr:
		return s.classify(e.X)
	case *ast.SliceExpr:
		// a re-slice shares the base's backing array
		return s.classify(e.X)
	case *ast.StarExpr:
		return s.classify(e.X)
	case *ast.UnaryExpr:
		return s.classify(e.X)
	case *ast.TypeAssertExpr:
		return s.classify(e.X)
	case *ast.CallExpr:
		if fn := s.c.calleeFunc(e); fn != nil && s.c.isFrozenObj(fn) {
			return owned // a frozen method returns immutable data, safe to embed
		}
		return s.callResultForm(e, 0)
	default:
		return owned
	}
}

// callResultForm resolves the ownership form of result i of a call, resolving a
// viaReceiver result against the call's receiver expression.
func (s *fnScope) callResultForm(call *ast.CallExpr, i int) form {
	if s.c.isCloneCall(call) {
		return owned
	}
	callee := s.c.calleeFunc(call)
	if callee == nil {
		return owned // unknown call: optimistic
	}
	switch s.c.resultForm(callee, i) {
	case owned:
		return owned
	case unconditional:
		return unconditional
	case viaReceiver:
		if sel, ok := unparen(call.Fun).(*ast.SelectorExpr); ok {
			return s.classify(sel.X)
		}
		return owned // viaReceiver without a receiver expr (e.g. method value): optimistic
	}
	return owned
}

// ---- phase A: inference -----------------------------------------------------

func (c *checker) infer() {
	type decl struct {
		fn   *types.Func
		body *ast.FuncDecl
	}
	var decls []decl
	for _, file := range c.pass.Files {
		for _, d := range file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if fn, ok := c.pass.TypesInfo.Defs[fd.Name].(*types.Func); ok {
				decls = append(decls, decl{fn, fd})
			}
		}
	}

	for changed := true; changed; {
		changed = false
		for _, d := range decls {
			forms := c.computeResultForms(d.fn, d.body)
			prev := c.local[d.fn]
			if prev == nil || !formsEqual(prev.Forms, forms) {
				c.local[d.fn] = &resultOwnership{Forms: forms}
				changed = true
			}
		}
	}

	for fn, rf := range c.local {
		if anyNonOwned(rf.Forms) {
			c.pass.ExportObjectFact(fn, rf)
		}
	}
}

func (c *checker) computeResultForms(fn *types.Func, body *ast.FuncDecl) []form {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Results().Len() == 0 {
		return nil
	}
	n := sig.Results().Len()
	forms := make([]form, n)

	// A //ownership:result annotation overrides inference entirely. `owned`
	// suppresses (e.g. an accessor that clones internally); `borrowed` forces
	// (e.g. a value reached through an interface inference can't see).
	if ann, ok := resultAnnotation(body.Doc); ok {
		for i := range forms {
			if ann == owned {
				forms[i] = owned
			} else if isMapOrSlice(sig.Results().At(i).Type()) {
				forms[i] = unconditional
			}
		}
		return forms
	}

	s := c.newScope(body)
	ast.Inspect(body.Body, func(node ast.Node) bool {
		if _, ok := node.(*ast.FuncLit); ok {
			return false // don't attribute a closure's returns to this function
		}
		ret, ok := node.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		switch {
		case len(ret.Results) == n:
			for i, r := range ret.Results {
				forms[i] = moreBorrowed(forms[i], s.classify(r))
			}
		case len(ret.Results) == 1 && n > 1:
			if call, ok := unparen(ret.Results[0]).(*ast.CallExpr); ok {
				for i := range forms {
					forms[i] = moreBorrowed(forms[i], s.callResultForm(call, i))
				}
			}
		}
		return true
	})
	return forms
}

func (c *checker) resultForm(fn *types.Func, i int) form {
	fn = fn.Origin() // generic instantiations share the origin's fact
	if rf, ok := c.local[fn]; ok {
		if i < len(rf.Forms) {
			return rf.Forms[i]
		}
		return owned
	}
	var f resultOwnership
	if c.pass.ImportObjectFact(fn, &f) {
		if i < len(f.Forms) {
			return f.Forms[i]
		}
	}
	return owned
}

// ---- phase A2: parameter effect summaries ----------------------------------

// summarize computes, per function, which parameters it mutates or embeds into an
// escaping proto, to a fixpoint, and exports the non-trivial summaries.
func (c *checker) summarize() {
	type decl struct {
		fn   *types.Func
		body *ast.FuncDecl
	}
	var decls []decl
	for _, file := range c.pass.Files {
		for _, d := range file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if fn, ok := c.pass.TypesInfo.Defs[fd.Name].(*types.Func); ok {
				decls = append(decls, decl{fn, fd})
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for _, d := range decls {
			sum := c.computeParamSummary(d.fn, d.body)
			prev := c.summaries[d.fn]
			if prev == nil || !boolsEqual(prev.Mutated, sum.Mutated) || !boolsEqual(prev.Embedded, sum.Embedded) {
				c.summaries[d.fn] = sum
				changed = true
			}
		}
	}
	for fn, sum := range c.summaries {
		if anyBool(sum.Mutated) || anyBool(sum.Embedded) {
			c.pass.ExportObjectFact(fn, sum)
		}
	}
}

func (c *checker) computeParamSummary(fn *types.Func, fd *ast.FuncDecl) *paramSummary {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Params().Len() == 0 {
		return &paramSummary{}
	}
	n := sig.Params().Len()
	sum := &paramSummary{Mutated: make([]bool, n), Embedded: make([]bool, n)}
	pIndex := c.paramIndex(fd)
	rootParam := func(e ast.Expr) int { return c.rootParam(e, pIndex) }

	ast.Inspect(fd.Body, func(node ast.Node) bool {
		switch stmt := node.(type) {
		case *ast.AssignStmt:
			for _, lhs := range stmt.Lhs {
				if base, _ := writeTarget(lhs); base != nil {
					if i := rootParam(base); i >= 0 {
						sum.Mutated[i] = true
					}
				}
			}
		case *ast.IncDecStmt:
			if base, _ := writeTarget(stmt.X); base != nil {
				if i := rootParam(base); i >= 0 {
					sum.Mutated[i] = true
				}
			}
		case *ast.CallExpr:
			if name, ok := c.builtinName(stmt); ok {
				if (name == "append" || name == "delete" || name == "clear") && len(stmt.Args) > 0 {
					if i := rootParam(stmt.Args[0]); i >= 0 {
						sum.Mutated[i] = true
					}
				}
				return true
			}
			callee := c.calleeFunc(stmt)
			if callee == nil {
				return true
			}
			cs := c.paramSummaryOf(callee)
			if cs == nil {
				return true
			}
			for j, arg := range stmt.Args {
				i := rootParam(arg)
				if i < 0 {
					continue
				}
				if j < len(cs.Mutated) && cs.Mutated[j] {
					sum.Mutated[i] = true
				}
				if j < len(cs.Embedded) && cs.Embedded[j] {
					sum.Embedded[i] = true
				}
			}
		}
		return true
	})

	// Embedded: a param embedded into a *protobuf* that escapes this function.
	// (Embedding into a non-proto struct is not the marshal hazard.)
	esc := c.escapingVars(fd)
	for cl := range c.escapingLits(fd, esc) {
		if t := c.pass.TypesInfo.TypeOf(cl); t == nil || !c.isProtoMessage(t) {
			continue
		}
		for _, elt := range cl.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			vt := c.pass.TypesInfo.TypeOf(kv.Value)
			if vt != nil && isMapOrSlice(vt) {
				if i := rootParam(kv.Value); i >= 0 {
					sum.Embedded[i] = true
				}
			}
		}
	}
	ast.Inspect(fd.Body, func(node ast.Node) bool {
		as, ok := node.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != len(as.Rhs) {
			return true
		}
		for k, lhs := range as.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if ft := c.pass.TypesInfo.TypeOf(sel); ft == nil || !isMapOrSlice(ft) {
				continue
			}
			if h := c.pass.TypesInfo.TypeOf(sel.X); h == nil || !c.isProtoMessage(h) {
				continue
			}
			if v := c.rootVar(sel.X); v == nil || !esc[v] {
				continue
			}
			if i := rootParam(as.Rhs[k]); i >= 0 {
				sum.Embedded[i] = true
			}
		}
		return true
	})
	return sum
}

// paramIndex maps each named parameter (and locals aliased directly from one) to
// its parameter position.
func (c *checker) paramIndex(fd *ast.FuncDecl) map[*types.Var]int {
	idx := map[*types.Var]int{}
	if fd.Type.Params == nil {
		return idx
	}
	pos := 0
	for _, field := range fd.Type.Params.List {
		if len(field.Names) == 0 {
			pos++
			continue
		}
		for _, name := range field.Names {
			if v, ok := c.pass.TypesInfo.Defs[name].(*types.Var); ok {
				idx[v] = pos
			}
			pos++
		}
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != len(as.Rhs) {
			return true
		}
		for k, lhs := range as.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok {
				continue
			}
			if v, ok := c.pass.TypesInfo.ObjectOf(id).(*types.Var); ok {
				if i := c.rootParam(as.Rhs[k], idx); i >= 0 {
					idx[v] = i
				}
			}
		}
		return true
	})
	return idx
}

// rootParam returns the parameter index expr roots to (via projection/alias), or -1.
func (c *checker) rootParam(expr ast.Expr, pIndex map[*types.Var]int) int {
	switch e := unparen(expr).(type) {
	case *ast.Ident:
		if v, ok := c.pass.TypesInfo.ObjectOf(e).(*types.Var); ok {
			if i, found := pIndex[v]; found {
				return i
			}
		}
	case *ast.SelectorExpr:
		return c.rootParam(e.X, pIndex)
	case *ast.IndexExpr:
		return c.rootParam(e.X, pIndex)
	case *ast.SliceExpr:
		return c.rootParam(e.X, pIndex)
	case *ast.StarExpr:
		return c.rootParam(e.X, pIndex)
	case *ast.TypeAssertExpr:
		return c.rootParam(e.X, pIndex)
	}
	return -1
}

func (c *checker) paramSummaryOf(fn *types.Func) *paramSummary {
	fn = fn.Origin()
	if s, ok := c.summaries[fn]; ok {
		return s
	}
	var s paramSummary
	if c.pass.ImportObjectFact(fn, &s) {
		return &s
	}
	return nil
}

// ---- phase B: sink check ----------------------------------------------------

func (c *checker) report() {
	for _, file := range c.pass.Files {
		if f := c.pass.Fset.File(file.Pos()); f != nil && strings.HasSuffix(f.Name(), "_test.go") {
			continue // responses aren't built in tests; skip to avoid noise
		}
		ignore := c.ignoreLines(file)
		for _, d := range file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || !fd.Name.IsExported() {
				continue
			}
			s := c.newScope(fd)
			// Only consider protos that actually escape the function (are
			// returned, transitively, or assigned into a returned proto). A proto
			// that is deep-cloned in place, marshaled synchronously, or read
			// locally never reaches an out-of-lock marshal, so its borrowed fields
			// are safe.
			esc := c.escapingVars(fd)
			for cl := range c.escapingLits(fd, esc) {
				c.checkLiteral(s, cl, ignore) // sink: borrowed field in an escaping proto literal
			}
			c.checkFieldAssigns(fd, s, esc, ignore) // sink: resp.Field = borrowed
			c.checkBorrowedCallArgs(fd, s, ignore)  // sink: f(borrowed) where f embeds the param
		}
	}
}

// checkBorrowedCallArgs flags a borrowed map/slice passed to a parameter that the
// callee embeds into an escaping proto (the borrowed value leaks through the call).
func (c *checker) checkBorrowedCallArgs(fd *ast.FuncDecl, s *fnScope, ignore map[int]bool) {
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee := c.calleeFunc(call)
		if callee == nil {
			return true
		}
		cs := c.paramSummaryOf(callee)
		if cs == nil {
			return true
		}
		for j, arg := range call.Args {
			if j >= len(cs.Embedded) || !cs.Embedded[j] {
				continue
			}
			at := c.pass.TypesInfo.TypeOf(arg)
			if at == nil || !isMapOrSlice(at) || s.classify(arg) == owned {
				continue
			}
			line := c.pass.Fset.Position(arg.Pos()).Line
			if ignore[line] || ignore[line-1] {
				continue
			}
			c.pass.Reportf(arg.Pos(),
				"borrowed %s passed to %s, which embeds it into a response without clone; "+
					"clone it (e.g. maps.Clone) first",
				kindOf(at), callee.Name())
		}
		return true
	})
}

// escapingVars returns the set of local variables whose value reaches a return
// statement (directly or via a simple alias chain), plus proto-pointer parameters
// (output protos the caller owns and may marshal).
func (c *checker) escapingVars(fd *ast.FuncDecl) map[*types.Var]bool {
	esc := map[*types.Var]bool{}
	if fd.Type.Params != nil {
		for _, field := range fd.Type.Params.List {
			for _, name := range field.Names {
				v, ok := c.pass.TypesInfo.Defs[name].(*types.Var)
				if !ok {
					continue
				}
				if ptr, ok := v.Type().(*types.Pointer); ok && c.isProtoMessage(ptr.Elem()) {
					esc[v] = true // output parameter: caller owns and may marshal it
				}
			}
		}
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if ret, ok := n.(*ast.ReturnStmt); ok {
			for _, r := range ret.Results {
				if v := c.identVar(returnedExpr(r)); v != nil {
					esc[v] = true
				}
			}
		}
		return true
	})
	for changed := true; changed; {
		changed = false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if _, ok := n.(*ast.FuncLit); ok {
				return false
			}
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != len(as.Rhs) {
				return true
			}
			for i, lhs := range as.Lhs {
				lv := c.identVar(lhs)
				if lv == nil || !esc[lv] {
					continue
				}
				if rv := c.identVar(returnedExpr(as.Rhs[i])); rv != nil && !esc[rv] {
					esc[rv] = true
					changed = true
				}
			}
			return true
		})
	}
	return esc
}

// escapingLits returns the composite literals that escape: directly returned (or
// nested within a returned literal), or assigned to an escaping variable or a
// field of one. Descent stops at call boundaries, so `return Clone(&T{...})` and
// `p := &T{...}; return p.Marshal()` do not mark the literal as escaping.
func (c *checker) escapingLits(fd *ast.FuncDecl, esc map[*types.Var]bool) map[*ast.CompositeLit]bool {
	lits := map[*ast.CompositeLit]bool{}
	var collect func(ast.Expr)
	collect = func(e ast.Expr) {
		switch x := unparen(e).(type) {
		case *ast.UnaryExpr:
			collect(x.X)
		case *ast.CompositeLit:
			lits[x] = true
			for _, elt := range x.Elts {
				v := elt
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					v = kv.Value
				}
				collect(v)
			}
		}
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		switch node := n.(type) {
		case *ast.ReturnStmt:
			for _, r := range node.Results {
				collect(r)
			}
		case *ast.AssignStmt:
			if len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, lhs := range node.Lhs {
				if v := c.rootVar(lhs); v != nil && esc[v] {
					collect(node.Rhs[i])
				}
			}
		}
		return true
	})
	return lits
}

// checkFieldAssigns flags `target.Field = borrowed` where target is (rooted at)
// an escaping proto and Field is a map/slice. Literal RHS values are handled by
// escapingLits (their own fields are checked there).
func (c *checker) checkFieldAssigns(fd *ast.FuncDecl, s *fnScope, esc map[*types.Var]bool, ignore map[int]bool) {
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != len(as.Rhs) {
			return true
		}
		for i, lhs := range as.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			ft := c.pass.TypesInfo.TypeOf(sel)
			if ft == nil || !isMapOrSlice(ft) {
				continue
			}
			holder := c.pass.TypesInfo.TypeOf(sel.X)
			if holder == nil || !c.isProtoMessage(holder) {
				continue
			}
			v := c.rootVar(sel.X)
			if v == nil || !esc[v] {
				continue
			}
			rhs := as.Rhs[i]
			if _, isLit := unparen(rhs).(*ast.CompositeLit); isLit {
				continue
			}
			if s.classify(rhs) == owned {
				continue
			}
			line := c.pass.Fset.Position(rhs.Pos()).Line
			if ignore[line] || ignore[line-1] {
				continue
			}
			c.pass.Reportf(rhs.Pos(),
				"borrowed %s assigned to proto field %s without clone; "+
					"clone it (e.g. maps.Clone) before assigning to avoid a "+
					"concurrent-access crash while the response is marshaled",
				kindOf(ft), sel.Sel.Name)
		}
		return true
	})
}

// returnedExpr unwraps parens and a leading address-of so a returned `&x` or
// `(x)` resolves to its underlying expression.
func returnedExpr(e ast.Expr) ast.Expr {
	e = unparen(e)
	if u, ok := e.(*ast.UnaryExpr); ok {
		return unparen(u.X)
	}
	return e
}

// rootVar walks selector/index/deref chains to the base identifier's variable.
func (c *checker) rootVar(e ast.Expr) *types.Var {
	for {
		switch x := unparen(e).(type) {
		case *ast.SelectorExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		default:
			return c.identVar(unparen(e))
		}
	}
}

func (c *checker) identVar(e ast.Expr) *types.Var {
	id, ok := e.(*ast.Ident)
	if !ok {
		return nil
	}
	v, _ := c.pass.TypesInfo.ObjectOf(id).(*types.Var)
	return v
}

func (c *checker) checkLiteral(s *fnScope, cl *ast.CompositeLit, ignore map[int]bool) {
	t := c.pass.TypesInfo.TypeOf(cl)
	if t == nil || !c.isProtoMessage(t) {
		return
	}
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		vt := c.pass.TypesInfo.TypeOf(kv.Value)
		if vt == nil || !isMapOrSlice(vt) {
			continue
		}
		if s.classify(kv.Value) == owned {
			continue
		}
		line := c.pass.Fset.Position(kv.Value.Pos()).Line
		if ignore[line] || ignore[line-1] {
			continue // //ownership:ignore on the embed line or the line above
		}
		c.pass.Reportf(kv.Value.Pos(),
			"borrowed %s embedded into proto field %s without clone; "+
				"clone it (e.g. maps.Clone) before embedding to avoid a "+
				"concurrent-access crash while the response is marshaled",
			kindOf(vt), fieldName(kv.Key))
	}
}

// ---- directives -------------------------------------------------------------

var (
	reResultAnnotation = regexp.MustCompile(`//ownership:result\s+(owned|borrowed)\b`)
	// //ownership:ignore REQUIRES a reason (the trailing \S.*), so suppressions
	// are reviewable rather than silent.
	reIgnore = regexp.MustCompile(`//ownership:ignore\s+\S`)
	reFrozen = regexp.MustCompile(`//ownership:frozen\b`)
)

// frozenAnnotated reports whether a doc comment carries //ownership:frozen.
func frozenAnnotated(doc *ast.CommentGroup) bool {
	if doc == nil {
		return false
	}
	for _, com := range doc.List {
		if reFrozen.MatchString(com.Text) {
			return true
		}
	}
	return false
}

// resultAnnotation returns (owned, true) for //ownership:result owned, or
// (unconditional, true) for //ownership:result borrowed; (owned, false) if absent.
func resultAnnotation(doc *ast.CommentGroup) (form, bool) {
	if doc == nil {
		return owned, false
	}
	for _, com := range doc.List {
		if m := reResultAnnotation.FindStringSubmatch(com.Text); m != nil {
			if m[1] == "owned" {
				return owned, true
			}
			return unconditional, true
		}
	}
	return owned, false
}

// ignoreLines returns the set of source lines carrying a //ownership:ignore
// directive (with a reason) anywhere in the file.
func (c *checker) ignoreLines(file *ast.File) map[int]bool {
	lines := map[int]bool{}
	for _, cg := range file.Comments {
		for _, com := range cg.List {
			if reIgnore.MatchString(com.Text) {
				lines[c.pass.Fset.Position(com.Pos()).Line] = true
			}
		}
	}
	return lines
}

// ---- callee resolution & helpers -------------------------------------------

func (c *checker) calleeFunc(call *ast.CallExpr) *types.Func {
	switch fun := unparen(call.Fun).(type) {
	case *ast.Ident:
		fn, _ := c.pass.TypesInfo.ObjectOf(fun).(*types.Func)
		return fn
	case *ast.SelectorExpr:
		fn, _ := c.pass.TypesInfo.ObjectOf(fun.Sel).(*types.Func)
		return fn
	}
	return nil
}

func (c *checker) isCloneCall(call *ast.CallExpr) bool {
	sel, ok := unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return c.clone[pkg.Name][sel.Sel.Name]
}

func (c *checker) isProtoMessage(t types.Type) bool {
	if v, ok := c.proto[t]; ok {
		return v
	}
	v := hasProtoReflect(t)
	c.proto[t] = v
	return v
}

func hasProtoReflect(t types.Type) bool {
	for _, typ := range []types.Type{t, types.NewPointer(t)} {
		ms := types.NewMethodSet(typ)
		for i := 0; i < ms.Len(); i++ {
			if ms.At(i).Obj().Name() == "ProtoReflect" {
				return true
			}
		}
	}
	return false
}

func isMapOrSlice(t types.Type) bool {
	switch t.Underlying().(type) {
	case *types.Map, *types.Slice:
		return true
	}
	return false
}

func kindOf(t types.Type) string {
	if _, ok := t.Underlying().(*types.Slice); ok {
		return "slice"
	}
	return "map"
}

func fieldName(key ast.Expr) string {
	if id, ok := key.(*ast.Ident); ok {
		return id.Name
	}
	return "?"
}

func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

func formsEqual(a, b []form) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func anyNonOwned(forms []form) bool {
	for _, f := range forms {
		if f != owned {
			return true
		}
	}
	return false
}
