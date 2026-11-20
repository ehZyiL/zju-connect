package desktop

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
)

type control struct {
	ctx         context.Context
	cancel      context.CancelFunc
	session     string
	encoder     *json.Encoder
	writeMu     sync.Mutex
	mu          sync.Mutex
	sequence    uint64
	pendingID   string
	pending     chan string
	dnsMu       sync.Mutex
	dnsHandler  dnsExchange
	dnsPending  map[string]context.CancelFunc
	dnsWG       sync.WaitGroup
	flowMu      sync.Mutex
	flowPending map[string]*flowRequest
	flowSlots   chan struct{}
}

func (c *control) emit(m Message) error {
	m.Version, m.Session = Version, c.session
	if b, err := json.Marshal(m); err != nil || len(b) >= MaxMessage {
		return errors.New("worker message exceeds size limit")
	}
	c.writeMu.Lock()
	err := c.encoder.Encode(m)
	c.writeMu.Unlock()
	if err != nil {
		c.cancel()
	}
	return err
}

func (c *control) ask(kind string, image []byte) (string, error) {
	if len(image) > 512<<10 {
		return "", errors.New("captcha image too large")
	}
	c.mu.Lock()
	c.sequence++
	id := strconv.FormatUint(c.sequence, 10)
	answer := make(chan string, 1)
	c.pendingID, c.pending = id, answer
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.pendingID, c.pending = "", nil; c.mu.Unlock() }()
	if err := c.emit(Message{Type: "challenge", ChallengeID: id, Kind: kind, Image: image}); err != nil {
		return "", err
	}
	select {
	case <-c.ctx.Done():
		return "", c.ctx.Err()
	case value := <-answer:
		return value, nil
	}
}

func (c *control) accept(m Message) bool {
	if m.Version != Version || m.Session != c.session {
		return false
	}
	if m.Type == "stop" {
		c.cancel()
		return false
	}
	if m.Type == "dns_query" || m.Type == "dns_cancel" {
		return c.acceptDNS(m)
	}
	if m.Type == "flow_cancel" || m.Type == "flow_prepare" {
		return c.acceptFlow(m)
	}
	if m.Type != "answer" || len(m.Answer) > 1024 || strings.TrimSpace(m.Answer) == "" {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != nil && m.ChallengeID == c.pendingID {
		select {
		case c.pending <- strings.TrimSpace(m.Answer):
		default:
		}
		c.pendingID = "" // an answer can be consumed only once
	}
	return true
}

func (c *control) stopFlow() {
	c.flowMu.Lock()
	for _, request := range c.flowPending {
		request.cancel()
	}
	c.flowPending = nil
	c.flowMu.Unlock()
}

func scanMessages(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 4096), MaxMessage)
	return s
}
