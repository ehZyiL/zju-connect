package desktop

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/mythologyli/zju-connect/dial"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 16*1024)
		return &b
	},
}

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
	return socks5.NewServer(
		socks5.WithAuthMethods([]socks5.Authenticator{socks5.UserPassAuthenticator{Credentials: flowCredentials{cfg.SocksUser, cfg.SocksPassword}}}),
		socks5.WithResolver(deferredFlowResolver{}),
		socks5.WithRule(&socks5.PermitCommand{EnableConnect: true}),
		socks5.WithDialAndRequest(func(_ context.Context, network, addr string, req *socks5.Request) (net.Conn, error) {
			return desktopDial(c, cfg, req, network, addr, aliases.dialFlow)
		}),
	)
}

func newDesktopVPNOnlySOCKS(c *control, cfg Config, aliases *captureAliases, allowUDP bool) *socks5.Server {
	udpFlows := make(chan struct{}, maxUDPAssociations)
	return socks5.NewServer(
		socks5.WithAuthMethods([]socks5.Authenticator{socks5.UserPassAuthenticator{Credentials: flowCredentials{cfg.SocksUser, cfg.SocksPassword}}}),
		socks5.WithResolver(deferredFlowResolver{}),
		socks5.WithRule(&socks5.PermitCommand{EnableConnect: true, EnableAssociate: allowUDP}),
		socks5.WithAssociateHandle(func(_ context.Context, writer io.Writer, req *socks5.Request) error {
			if flowID(req.AuthContext.Payload["username"], cfg.SocksUser) == "" {
				return socks5.SendReply(writer, statute.RepRuleFailure, nil)
			}
			return serveStrictUDP(c.ctx, writer, req, udpFlows, func(ctx context.Context, network, target string) (net.Conn, error) {
				return desktopDialContext(ctx, c, cfg, req, network, target, aliases.dialStrictVPNFlow)
			})
		}),
		socks5.WithConnectHandle(func(_ context.Context, writer io.Writer, req *socks5.Request) error {
			addr := req.DestAddr.String()
			conn, err := desktopDial(c, cfg, req, "tcp", addr, aliases.dialStrictVPNFlow)
			if err != nil {
				resp := statute.RepHostUnreachable
				if errors.Is(err, dial.ErrACLDenied) {
					resp = statute.RepRuleFailure
				} else if strings.Contains(err.Error(), "refused") {
					resp = statute.RepConnectionRefused
				} else if errors.Is(err, context.Canceled) {
					resp = statute.RepHostUnreachable
				}
				_ = socks5.SendReply(writer, resp, nil)
				return err
			}
			defer conn.Close()
			if err := socks5.SendReply(writer, statute.RepSuccess, conn.LocalAddr()); err != nil {
				return err
			}
			errCh := make(chan error, 2)
			go func() {
				buf := copyBufPool.Get().(*[]byte)
				defer copyBufPool.Put(buf)
				_, copyErr := io.CopyBuffer(conn, req.Reader, *buf)
				if cw, ok := conn.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
				errCh <- copyErr
			}()
			go func() {
				buf := copyBufPool.Get().(*[]byte)
				defer copyBufPool.Put(buf)
				_, copyErr := io.CopyBuffer(writer, conn, *buf)
				if cw, ok := writer.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
				errCh <- copyErr
			}()
			for i := 0; i < 2; i++ {
				if e := <-errCh; e != nil && !errors.Is(e, io.EOF) && !errors.Is(e, net.ErrClosed) {
					return e
				}
			}
			return nil
		}),
	)
}

func desktopDial(c *control, cfg Config, req *socks5.Request, network, addr string, dialFlow func(context.Context, string, string) (net.Conn, FlowResult, error)) (net.Conn, error) {
	return desktopDialContext(c.ctx, c, cfg, req, network, addr, dialFlow)
}

func desktopDialContext(parent context.Context, c *control, cfg Config, req *socks5.Request, network, addr string, dialFlow func(context.Context, string, string) (net.Conn, FlowResult, error)) (net.Conn, error) {
	id := flowID(req.AuthContext.Payload["username"], cfg.SocksUser)
	ctx, finish, err := c.beginFlow(id)
	result := FlowResult{Target: addr, Route: "unknown"}
	var conn net.Conn
	if err == nil {
		dialCtx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(parent, cancel)
		if parent.Err() != nil {
			cancel()
		}
		conn, result, err = dialFlow(dialCtx, network, addr)
		if err == nil && (dialCtx.Err() != nil || parent.Err() != nil) {
			err = context.Canceled
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			if conn != nil {
				conn.Close()
				conn = nil
			}
		}
		stop()
		cancel()
		// A dial deadline governs connection establishment, never stream life.
		finish()
	}
	if err != nil && result.Failure == "" {
		result.Failure = flowFailure(err)
	}
	if id != "" && c.ctx.Err() == nil {
		if emitErr := c.emit(Message{Type: "flow_result", RequestID: id, Flow: &result}); emitErr != nil {
			if conn != nil {
				conn.Close()
			}
			return nil, emitErr
		}
	}
	return conn, err
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

func (a *captureAliases) dialStrictVPNFlow(ctx context.Context, network, address string) (net.Conn, FlowResult, error) {
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
	conn, err := a.dialStrictVPNTarget(ctx, network, address)
	if err != nil {
		result.Failure = flowFailure(err)
		if errors.Is(err, errFlowDNS) {
			result.Rule = "dns"
		}
		if errors.Is(err, errCaptureAlias) {
			result.Route, result.Rule = "blocked", "alias"
		}
		if errors.Is(err, dial.ErrACLDenied) && result.Route == "unknown" {
			result.Route, result.Rule = "blocked", "acl"
		}
	}
	return conn, result, err
}

func (a *captureAliases) dialStrictVPNTarget(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, dial.ErrACLDenied
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return nil, dial.ErrACLDenied
		}
	} else {
		var resIP net.IP
		ctx, resIP, err = a.resolver.ResolveVPN(ctx, host)
		if err != nil {
			return nil, errors.Join(errFlowDNS, err)
		}
		if resIP == nil {
			return nil, errFlowDNS
		}
		if resIP.To4() == nil {
			return nil, dial.ErrACLDenied
		}
		address = net.JoinHostPort(resIP.String(), port)
	}
	return a.DialStrictVPN(ctx, network, address)
}

func (a *captureAliases) DialStrictVPN(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	inside := a.pool != nil && a.prefix.Contains(ip)
	var target aliasTarget
	valid := false
	if inside {
		_, target, valid = a.pool.GetDomain(net.ParseIP(host))
		now := a.now()
		valid = valid && !now.IsZero() && now.Before(target.Expires)
	}
	a.mu.Unlock()
	if inside {
		if !valid {
			return nil, errCaptureAlias
		}
		if _, err = strconv.ParseUint(port, 10, 16); err != nil {
			return nil, err
		}
		ctx = a.resolver.DomainContext(ctx, target.Name)
		return a.dialer.DialVPNIPPort(ctx, network, net.JoinHostPort(target.IP.String(), port))
	}
	if network == "udp" && netip.MustParsePrefix(CaptureAliasBlock).Contains(ip.Unmap()) {
		return nil, errCaptureAlias
	}
	return a.dialer.DialVPNIPPort(ctx, network, address)
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
