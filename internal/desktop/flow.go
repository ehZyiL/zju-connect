package desktop

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/mythologyli/zju-connect/dial"
	"github.com/things-go/go-socks5"
)

var errFlowDNS = errors.New("destination DNS failed")
var errCaptureAlias = errors.New("capture alias expired or was never issued by this VPN session")

// A request ID travels in the private SOCKS username. The session password is
// still required. External proxy clients cannot choose an application's ID.
type flowCredentials struct{ user, password string }

func flowID(user, base string) string {
	id, ok := strings.CutPrefix(user, base+"/")
	if !ok || len(id) == 0 || len(id) > 20 || id[0] == '0' {
		return ""
	}
	for _, ch := range id {
		if ch < '0' || ch > '9' {
			return ""
		}
	}
	return id
}

func (a flowCredentials) Valid(user, password, _ string) bool {
	return (user == a.user || flowID(user, a.user) != "") &&
		subtle.ConstantTimeCompare([]byte(password), []byte(a.password)) == 1
}

// Resolve inside the request-aware dial callback so DNS failures are reported
// with the same ID as successful dials. The library retains the original FQDN
// when IP is nil; the real existing resolver is called exactly once below.
type deferredFlowResolver struct{}

func (deferredFlowResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

func newDesktopSOCKS(c *control, cfg Config, aliases *captureAliases) *socks5.Server {
	slots := make(chan struct{}, MaxFlowRequests)
	return socks5.NewServer(
		socks5.WithAuthMethods([]socks5.Authenticator{socks5.UserPassAuthenticator{Credentials: flowCredentials{cfg.SocksUser, cfg.SocksPassword}}}),
		socks5.WithResolver(deferredFlowResolver{}),
		socks5.WithRule(&socks5.PermitCommand{EnableConnect: true}),
		socks5.WithDialAndRequest(func(_ context.Context, network, addr string, req *socks5.Request) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(c.ctx, 45*time.Second)
			defer cancel()
			id := flowID(req.AuthContext.Payload["username"], cfg.SocksUser)
			result := FlowResult{Target: addr, Route: "unknown"}
			var conn net.Conn
			var err error
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
				conn, result, err = aliases.dialFlow(ctx, network, addr)
			default:
				err = errors.New("too many pending connections")
				result.Failure = "busy"
			}
			// One bounded result per dial; do not stream packet/byte events on the
			// authentication pipe. GUI counters stay on the data connections.
			if id != "" && c.ctx.Err() == nil {
				if emitErr := c.emit(Message{Type: "flow_result", RequestID: id, Flow: &result}); emitErr != nil {
					if conn != nil {
						_ = conn.Close()
					}
					return nil, emitErr
				}
			}
			return conn, err
		}),
	)
}

func (a *captureAliases) dialFlow(ctx context.Context, network, address string) (net.Conn, FlowResult, error) {
	result := FlowResult{Target: address, Route: "unknown"}
	ctx = dial.WithDecisionObserver(ctx, func(d dial.Decision) {
		result.Route, result.Rule, result.DialAddress = d.Route, d.Rule, d.Address
		result.Domain, result.IPMin, result.IPMax = d.Domain, d.IPMin, d.IPMax
		result.PortMin, result.PortMax, result.Protocol = d.PortMin, d.PortMax, d.Protocol
		if d.Host != "" {
			if _, port, err := net.SplitHostPort(address); err == nil {
				result.Target = net.JoinHostPort(d.Host, port)
			}
		}
	})
	conn, err := a.dialTarget(ctx, network, address)
	if err != nil {
		result.Failure = flowFailure(err)
		if errors.Is(err, errFlowDNS) {
			result.Rule = "dns"
		}
		if errors.Is(err, errCaptureAlias) {
			result.Route, result.Rule = "blocked", "alias"
		}
	}
	return conn, result, err
}

func (a *captureAliases) dialTarget(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("desktop proxy supports TCP only")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) == nil {
		var ip net.IP
		ctx, ip, err = a.resolver.Resolve(ctx, host)
		if err != nil {
			return nil, errors.Join(errFlowDNS, err)
		}
		if ip == nil {
			return nil, errFlowDNS
		}
		address = net.JoinHostPort(ip.String(), port)
	}
	return a.Dial(ctx, network, address)
}

func flowFailure(err error) string {
	switch {
	case errors.Is(err, errFlowDNS):
		return "dns"
	case errors.Is(err, errCaptureAlias):
		return "alias"
	case errors.Is(err, dial.ErrACLDenied):
		return "denied"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "unreachable"
	}
	var n net.Error
	if errors.As(err, &n) && n.Timeout() {
		return "timeout"
	}
	return "connect"
}
