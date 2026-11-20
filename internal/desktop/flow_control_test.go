package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"
)

func flowControlFixture(t *testing.T) (*control, flowMessages) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	messages := make(flowMessages, MaxFlowRequests+4)
	c := &control{ctx: ctx, cancel: cancel, session: "test", encoder: json.NewEncoder(messages)}
	t.Cleanup(func() { cancel(); c.stopFlow() })
	return c, messages
}

func TestFlowCanceledBeforeSOCKSCannotStart(t *testing.T) {
	c, messages := flowControlFixture(t)
	prepareTestFlow(t, c, messages, "1")
	if !c.accept(Message{Version: Version, Session: c.session, Type: "flow_cancel", RequestID: "1"}) {
		t.Fatal("cancel rejected")
	}
	if _, finish, err := c.beginFlow("1"); !errors.Is(err, context.Canceled) {
		if finish != nil {
			finish()
		}
		t.Fatalf("late socket resurrected canceled dial: %v", err)
	}
}

func TestFlowDeadlineCancelsWithoutAnotherControlMessage(t *testing.T) {
	c, messages := flowControlFixture(t)
	deadline := time.Now().Add(100 * time.Millisecond)
	c.accept(Message{Version: Version, Session: c.session, Type: "flow_prepare", RequestID: "1", Deadline: deadline.UnixMilli()})
	if reply := <-messages; reply.Error != "" {
		t.Fatal(reply.Error)
	}
	ctx, finish, err := c.beginFlow("1")
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatal(ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("worker ignored caller deadline")
	}
}

func TestFlowPreparationBoundsAndDuplicateClaim(t *testing.T) {
	c, messages := flowControlFixture(t)
	for i := 1; i <= MaxFlowRequests; i++ {
		prepareTestFlow(t, c, messages, strconv.Itoa(i))
	}
	c.accept(Message{Version: Version, Session: c.session, Type: "flow_prepare", RequestID: "999", Deadline: time.Now().Add(time.Second).UnixMilli()})
	if reply := <-messages; reply.Error == "" {
		t.Fatal("unbounded preparation queue")
	}
	ctx, finish, err := c.beginFlow("1")
	if err != nil {
		t.Fatal(err)
	}
	if _, duplicateFinish, err := c.beginFlow("1"); err == nil {
		duplicateFinish()
		t.Fatal("duplicate socket claimed same request")
	}
	finish()
	if ctx.Err() == nil {
		t.Fatal("completed dial context retained")
	}
	prepareTestFlow(t, c, messages, "999")
	c.stopFlow()
	c.flowMu.Lock()
	defer c.flowMu.Unlock()
	if len(c.flowPending) != 0 || len(c.flowSlots) != 0 {
		t.Fatal("flow slots retained after completion/stop")
	}
}

func TestFlowRejectsExpiredOrWrongSessionPreparation(t *testing.T) {
	c, messages := flowControlFixture(t)
	if c.accept(Message{Version: Version, Session: "old", Type: "flow_prepare", RequestID: "1", Deadline: time.Now().Add(time.Second).UnixMilli()}) {
		t.Fatal("old session accepted")
	}
	c.accept(Message{Version: Version, Session: c.session, Type: "flow_prepare", RequestID: "2", Deadline: time.Now().Add(-time.Second).UnixMilli()})
	if reply := <-messages; reply.Error == "" {
		t.Fatal("expired request accepted")
	}
	if _, finish, err := c.beginFlow("2"); err == nil {
		finish()
		t.Fatal("expired socket started")
	}
}
