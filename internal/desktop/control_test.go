package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestChallengeRejectsStaleAnswersAndCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	c := &control{ctx: ctx, cancel: cancel, session: "test", encoder: json.NewEncoder(w)}
	result := make(chan string, 1)
	go func() { value, _ := c.ask("totp", nil); result <- value }()
	var challenge Message
	if err := json.NewDecoder(r).Decode(&challenge); err != nil {
		t.Fatal(err)
	}
	c.accept(Message{Version: Version, Session: "test", Type: "answer", ChallengeID: "old", Answer: "stale"})
	c.accept(Message{Version: Version, Session: "other", Type: "answer", ChallengeID: challenge.ChallengeID, Answer: "wrong session"})
	select {
	case <-result:
		t.Fatal("stale answer accepted")
	default:
	}
	c.accept(Message{Version: Version, Session: "test", Type: "answer", ChallengeID: challenge.ChallengeID, Answer: "current"})
	select {
	case value := <-result:
		if value != "current" {
			t.Fatal(value)
		}
	case <-time.After(time.Second):
		t.Fatal("answer not delivered")
	}
	failed := make(chan error, 1)
	go func() { _, err := c.ask("captcha", nil); failed <- err }()
	if err := json.NewDecoder(r).Decode(&challenge); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-failed; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestErrorDoesNotExposeServerResponse(t *testing.T) {
	for _, value := range []string{"password=secret TWFID=token", "<ErrorCode>20023</ErrorCode><TWFID>private</TWFID>"} {
		message := safeError(errors.New(value))
		if strings.Contains(message, "secret") || strings.Contains(message, "token") || strings.Contains(message, "private") {
			t.Fatal(message)
		}
	}
}
