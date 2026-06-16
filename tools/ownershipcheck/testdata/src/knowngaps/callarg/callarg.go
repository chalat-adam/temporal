// GAP FN-1 (false negative). Effort: L (per-callee param-retention facts).
// A borrowed map/slice embedded into a proto that is passed as a CALL ARGUMENT
// (not returned) is not flagged — escape is currently "returned" only. The callee
// may marshal/retain it (e.g. an RPC request). Mirrors
// replication/executable_activity_state_task.go's SyncActivities request.
//
// CURRENT: silent. DESIRED: flag the embed (callee marshals the request).
package callarg

type Payload struct{}

type Req struct {
	Fields map[string]*Payload
}

func (*Req) ProtoReflect() any { return nil }

type comp struct {
	memo map[string]*Payload
}

func send(*Req) {}

func (c *comp) Do() {
	send(&Req{Fields: c.memo}) // GAP: should be flagged (escapes via call arg)
}
