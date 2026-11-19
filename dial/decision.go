package dial

import (
	"context"

	"github.com/mythologyli/zju-connect/resolve"
)

// Decision describes the branch actually selected by the dialer, including
// failed attempts. It does not assert that a TCP connection or request succeeded.
type Decision struct {
	Route, Rule, Address, Host, Domain, IPMin, IPMax, Protocol string
	PortMin, PortMax                                           int
}

type decisionKey struct{}

// WithDecisionObserver is scoped to a single dial. It observes existing policy;
// it does not introduce a second resource matcher or change the routing rules.
func WithDecisionObserver(ctx context.Context, observer func(Decision)) context.Context {
	return context.WithValue(ctx, decisionKey{}, observer)
}

func reportDecision(ctx context.Context, decision Decision) {
	if fn, ok := ctx.Value(decisionKey{}).(func(Decision)); ok && fn != nil {
		decision.Host, _ = ctx.Value(resolve.ContextKeyResolveHost).(string)
		fn(decision)
	}
}
