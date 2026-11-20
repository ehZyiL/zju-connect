package desktop

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/mythologyli/zju-connect/client/authchallenge"
	"github.com/mythologyli/zju-connect/client/easyconnect"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/mythologyli/zju-connect/service"
	"github.com/mythologyli/zju-connect/stack"
	"github.com/mythologyli/zju-connect/stack/gvisor"
	"github.com/mythologyli/zju-connect/stack/tcptunnel"
	"github.com/mythologyli/zju-connect/underlay"
)

// Run owns one VPN session and one loopback listener until stop or pipe EOF.
// Long-lived stack cleanup is process-scoped, matching the upstream CLI.
func Run(input io.Reader, output io.Writer) (exitCode int) {
	scanner := scanMessages(input)
	if !scanner.Scan() {
		return 1
	}
	var first Message
	if json.Unmarshal(scanner.Bytes(), &first) != nil || first.Version != Version || first.Session == "" {
		return 1
	}
	if first.Type == "certificate_probe" && first.Config == nil {
		return probeCertificate(first, output)
	}
	if first.Type != "start" || first.Config == nil {
		return 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &control{ctx: ctx, cancel: cancel, session: first.Session, encoder: json.NewEncoder(output)}
	defer func() {
		if recover() != nil {
			_ = c.emit(Message{Type: "error", Error: "VPN 核心遇到异常，连接已结束"})
			exitCode = 1
		}
	}()
	go func() {
		defer cancel()
		for scanner.Scan() {
			var m Message
			if json.Unmarshal(scanner.Bytes(), &m) != nil || !c.accept(m) {
				return
			}
		}
	}()
	cfg := *first.Config
	first.Config = nil
	if err := validateConfig(cfg); err != nil {
		_ = c.emit(Message{Type: "error", Error: err.Error()})
		return 1
	}
	if err := serve(c, cfg); err != nil {
		if ctx.Err() == nil {
			_ = c.emit(Message{Type: "error", Error: safeError(err)})
		}
		return 1
	}
	return 0
}

func validateConfig(cfg Config) error {
	host, port, err := net.SplitHostPort(cfg.Server)
	if err != nil || host == "" || port == "" || strings.ContainsAny(host, "/?#@") {
		return errors.New("VPN 服务器地址无效")
	}
	if cfg.Username == "" || cfg.Password == "" || len(cfg.Password) > 8192 {
		return errors.New("需要账号和密码")
	}
	if cfg.SocksUser == "" || len(cfg.SocksUser) > 255 || len(cfg.SocksPassword) < 32 || len(cfg.SocksPassword) > 255 {
		return errors.New("内部代理凭据无效")
	}
	if cfg.RemoteDNS != "" && net.ParseIP(cfg.RemoteDNS).To4() == nil {
		return errors.New("VPN DNS 必须是 IPv4 地址")
	}
	if cfg.CertificateSHA256 != "" {
		b, err := hex.DecodeString(cfg.CertificateSHA256)
		if err != nil || len(b) != 32 {
			return errors.New("证书指纹无效")
		}
	}
	return nil
}

func serve(c *control, cfg Config) error {
	u, err := underlay.New(underlay.Options{})
	if err != nil {
		return err
	}
	defer u.Close()
	vpn := easyconnect.NewClient(easyconnect.Options{
		Server:            cfg.Server,
		Auth:              easyconnect.AuthOptions{Username: cfg.Username, Password: cfg.Password},
		Resources:         easyconnect.ResourceOptions{Fetch: true, IncludeDomains: true},
		UnderlayDialer:    u,
		DisableProxyEnv:   true,
		CertificateSHA256: cfg.CertificateSHA256,
		ChallengeHandler: authchallenge.HandlerFuncs{
			Code: func(ch authchallenge.CodeChallenge) (authchallenge.CodeResponse, error) {
				value, err := c.ask(string(ch.Kind), nil)
				return authchallenge.CodeResponse{Code: value}, err
			},
			TextCaptcha: func(ch authchallenge.TextCaptchaChallenge) (authchallenge.TextCaptchaResponse, error) {
				value, err := c.ask("captcha", ch.Image)
				return authchallenge.TextCaptchaResponse{Code: value}, err
			},
		},
	})
	cfg.Password = ""
	defer vpn.Close()
	stopClose := context.AfterFunc(c.ctx, vpn.Close)
	defer stopClose()
	if err := vpn.Setup(); err != nil {
		return err
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	ipResources, err := vpn.IPResources()
	if err != nil {
		return errors.New("资源配置不可用，无法安全选择 VPN 路由")
	}
	domains, _ := vpn.DomainResources()
	dnsResources, _ := vpn.DNSResource()
	remoteDNS := cfg.RemoteDNS
	if remoteDNS == "" {
		remoteDNS, _ = vpn.DNSServer()
	}
	var vpnStack stack.Stack
	if vpn.CanUseTCPTunnel() {
		vpnStack, err = tcptunnel.NewStack(vpn)
	} else {
		vpnStack, err = gvisor.NewStack(vpn)
	}
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = hook_func.ExecTerminalFunc(ctx)
	}()
	r := resolve.NewResolver(vpnStack, remoteDNS, "", 60, domains, dnsResources, remoteDNS != "")
	r.EnableSplitDNS(cfg.InternalDomains)
	defer r.Close()
	d := dial.NewDialer(vpnStack, r, ipResources, false, "")
	aliases := newCaptureAliases(r, ipResources, d)
	c.setDNSHandler(dnsHandler(r, ipResources, aliases))
	defer c.stopDNS()
	defer c.stopFlow()
	vpnStack.SetupResolve(service.NewDnsServer(r, []string{remoteDNS}))
	vpnStack.SetupIPPool(r.IPPool)
	go vpnStack.Run()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()

	vpnListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer vpnListener.Close()

	server := newDesktopSOCKS(c, cfg, aliases)
	vpnServer := newDesktopVPNOnlySOCKS(c, cfg, aliases)

	ip, _ := vpn.IP()
	resources := resourceSnapshot(ipResources, domains, dnsResources, cfg, remoteDNS, vpn.CanUseTCPTunnel())
	if err := c.emit(Message{
		Type:          "ready",
		Address:       listener.Addr().String(),
		VPNAddress:    vpnListener.Addr().String(),
		Capabilities:  []string{"strict_vpn", "flow_cancel", "flow_prepare"},
		ClientIP:      ip.String(),
		DNSServer:     remoteDNS,
		Resources:     resources,
		FlowReporting: true,
	}); err != nil {
		return err
	}
	served := make(chan error, 2)
	go func() { served <- server.Serve(listener) }()
	go func() { served <- vpnServer.Serve(vpnListener) }()
	select {
	case <-c.ctx.Done():
		return nil
	case err := <-served:
		return err
	}
}

var gatewayErrorCode = regexp.MustCompile(`(?i)ErrorCode[^0-9]{0,12}([0-9]{1,8})`)

// Never send upstream XML, credentials or session identifiers to the UI.
func safeError(err error) string {
	s := err.Error()
	var certInvalid x509.CertificateInvalidError
	var unknownAuth x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	lower := strings.ToLower(s)
	switch {
	case strings.Contains(s, "fingerprint"):
		return "网关证书与已信任的证书不同，连接已终止；请查看证书并核实变更"
	case strings.Contains(s, "SAN dNSName is malformed"):
		return "网关证书的域名字段格式不兼容；请点击「查看网关证书」，确认来源后重试"
	case errors.As(err, &unknownAuth) || errors.As(err, &certInvalid) || errors.As(err, &hostnameErr) ||
		strings.Contains(lower, "certificate signed by unknown authority") ||
		strings.Contains(lower, "x509: certificate") ||
		strings.Contains(lower, "certificate is not valid") ||
		strings.Contains(lower, "tls: failed to verify certificate"):
		return "网关证书不受系统信任或主机名不匹配；请点击「查看网关证书」，确认指纹后再连接"
	case strings.Contains(s, "资源配置不可用"):
		return "网关未返回可用资源配置，连接已终止"
	case errors.Is(err, context.Canceled):
		return "认证已取消"
	case errors.Is(err, context.DeadlineExceeded):
		return "连接超时，请重试"
	}
	if m := gatewayErrorCode.FindStringSubmatch(s); len(m) == 2 {
		return "网关拒绝认证，错误码 " + m[1] + "；请检查密码或验证码后重新连接"
	}
	var op *net.OpError
	if errors.As(err, &op) {
		return "无法连接 VPN 网关，请检查地址和网络"
	}
	return "VPN 认证或隧道建立失败，请检查账号、验证码及网关兼容性后重试"
}
