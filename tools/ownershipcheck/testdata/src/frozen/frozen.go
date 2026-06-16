// frozen: //ownership:frozen on a struct field or a method makes its data
// immutable — safe to embed even when read off the receiver, and any write to it
// (directly or through an alias) is flagged with the path back to the source.
package frozen

type Payload struct{}

type SearchAttributes struct {
	IndexedFields map[string]*Payload
}

func (*SearchAttributes) ProtoReflect() any { return nil }

type comp struct {
	//ownership:frozen
	cfg map[string]*Payload // want cfg:`frozen`

	mutable map[string]*Payload
}

// DescribeFrozen embeds a frozen field — immutable, so silent.
func (c *comp) DescribeFrozen() *SearchAttributes {
	return &SearchAttributes{IndexedFields: c.cfg}
}

// DescribeMutable embeds a non-frozen field — still flagged.
func (c *comp) DescribeMutable() *SearchAttributes {
	return &SearchAttributes{IndexedFields: c.mutable} // want `borrowed map embedded into proto field IndexedFields`
}

// WriteFrozen mutates frozen data directly.
func (c *comp) WriteFrozen() {
	c.cfg["k"] = &Payload{} // want `frozen data mutated`
}

// WriteViaAlias mutates frozen data through an alias (path: cfg -> m -> write).
func (c *comp) WriteViaAlias() {
	m := c.cfg
	delete(m, "k") // want `frozen data mutated`
}

// Config is a frozen method: its result is immutable.
//
//ownership:frozen
func (c *comp) Config() map[string]*Payload { // want Config:`frozen`
	return c.cfg
}

// MutateConfigResult mutates the result of a frozen method.
func (c *comp) MutateConfigResult() {
	cfg := c.Config()
	cfg["k"] = &Payload{} // want `frozen data mutated`
}

// mutate writes its parameter (summarized as mutating param 0).
func mutate(m map[string]*Payload) { // want mutate:`mutates param`
	m["k"] = &Payload{}
}

// MutateViaCallee passes frozen data to a function that mutates it (interprocedural).
func (c *comp) MutateViaCallee() {
	mutate(c.cfg) // want `frozen data passed to mutate, which mutates it`
}
