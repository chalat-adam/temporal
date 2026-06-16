// GAP FP-4 (false positive — judgment call). EVALUATED: a sweep of
// chasm+service+common produced 0 []byte findings, so the hypothesized noise does
// not exist. Excluding []byte would only lose recall (a mutable []byte buffer
// embedded into a response can race too) for no precision gain, so we keep
// flagging []byte. Kept as documentation; re-evaluate only if []byte false
// positives actually appear.
//
// CURRENT: flagged. DECISION: keep flagging (do not special-case []byte).
package bytetoken

type Resp struct {
	Token []byte
}

func (*Resp) ProtoReflect() any { return nil }

type comp struct {
	token []byte // immutable serialized token
}

func (c *comp) Describe() *Resp {
	return &Resp{Token: c.token} // GAP: flagged today; token is immutable
}
