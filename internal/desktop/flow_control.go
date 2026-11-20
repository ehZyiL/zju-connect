package desktop

import (
	"context"
	"errors"
	"time"
)

type flowRequest struct {
	ctx     context.Context
	cancel  context.CancelFunc
	started bool
}

// The Hub waits for flow_ready before opening SOCKS. A canceled/expired
// preparation is removed, so a delayed socket can never resurrect its dial.
func (c *control) acceptFlow(m Message) bool {
	if flowID("hub/"+m.RequestID, "hub") == "" {
		return false
	}
	c.flowMu.Lock()
	if m.Type == "flow_cancel" {
		if request := c.flowPending[m.RequestID]; request != nil {
			delete(c.flowPending, m.RequestID)
			request.cancel()
		}
		c.flowMu.Unlock()
		return true
	}
	deadline := time.UnixMilli(m.Deadline)
	if maxDeadline := time.Now().Add(45 * time.Second); deadline.After(maxDeadline) {
		deadline = maxDeadline
	}
	if c.ctx.Err() != nil || !deadline.After(time.Now()) || len(c.flowPending) >= MaxFlowRequests || c.flowPending[m.RequestID] != nil {
		c.flowMu.Unlock()
		return c.emit(Message{Type: "flow_ready", RequestID: m.RequestID, Error: "flow unavailable, expired or busy"}) == nil
	}
	ctx, cancel := context.WithDeadline(c.ctx, deadline)
	request := &flowRequest{ctx: ctx, cancel: cancel}
	if c.flowPending == nil {
		c.flowPending = make(map[string]*flowRequest)
	}
	c.flowPending[m.RequestID] = request
	c.flowMu.Unlock()
	context.AfterFunc(ctx, func() { c.finishFlow(m.RequestID, request) })
	return c.emit(Message{Type: "flow_ready", RequestID: m.RequestID}) == nil
}

func (c *control) finishFlow(id string, request *flowRequest) {
	c.flowMu.Lock()
	if c.flowPending[id] == request {
		delete(c.flowPending, id)
	}
	c.flowMu.Unlock()
	request.cancel()
}

func (c *control) beginFlow(id string) (context.Context, func(), error) {
	c.flowMu.Lock()
	if c.flowSlots == nil {
		c.flowSlots = make(chan struct{}, MaxFlowRequests)
	}
	slots := c.flowSlots
	var request *flowRequest
	if id != "" {
		request = c.flowPending[id]
		if request == nil || request.started || request.ctx.Err() != nil {
			c.flowMu.Unlock()
			return nil, nil, context.Canceled
		}
		request.started = true
	}
	c.flowMu.Unlock()
	ctx, cancel := context.WithTimeout(c.ctx, 45*time.Second)
	if request != nil {
		cancel()
		ctx = request.ctx
		cancel = func() { c.finishFlow(id, request) }
	}
	if err := ctx.Err(); err != nil {
		cancel()
		return nil, nil, err
	}
	select {
	case slots <- struct{}{}:
		return ctx, func() { <-slots; cancel() }, nil
	default:
		cancel()
		return nil, nil, errors.New("too many pending connections")
	}
}
