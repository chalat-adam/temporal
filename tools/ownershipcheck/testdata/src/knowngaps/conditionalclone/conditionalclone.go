// GAP FP-3 (false positive / false negative). Effort: L (flow-sensitive / SSA).
// collectLocals is flow-insensitive (last assignment in source order wins), so a
// conditional clone is misclassified. Here the last write is the clone, so the
// embed is treated as owned even though the `else` path embeds the borrowed map
// (a false negative); reorder the branches and it becomes a false positive.
//
// CURRENT: depends on source order, not control flow. DESIRED: flow-sensitive.
package conditionalclone

import "maps"

type Payload struct{}

type Resp struct {
	Fields map[string]*Payload
}

func (*Resp) ProtoReflect() any { return nil }

type comp struct {
	memo map[string]*Payload
}

func (c *comp) Describe(rare bool) *Resp {
	m := c.memo
	if !rare {
		m = maps.Clone(c.memo)
	}
	return &Resp{Fields: m} // GAP: classified by the last assignment, not the live path
}
