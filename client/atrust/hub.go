package atrust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mythologyli/zju-connect/client/atrust/auth"
	"github.com/mythologyli/zju-connect/underlay"
)

// ResourceData returns the clientResource JSON Setup parsed, for debugging
// the workbench list.
func (c *Client) ResourceData() []byte {
	return append([]byte(nil), c.resourceData...)
}

// Apps returns the applications the server published to this user, for a
// workbench view. It is filled by Setup.
func (c *Client) Apps() []App {
	out := make([]App, len(c.apps))
	copy(out, c.apps)
	for i := range out {
		out[i].Addresses = append([]AppAddress(nil), out[i].Addresses...)
	}
	return out
}

// ClientData returns the cookies and device id of this session in the same
// shape Setup accepts, so a helper process can resume it without logging in
// again — a second login would drop this session.
func (c *Client) ClientData() ([]byte, error) {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	return json.Marshal(c.authData)
}

// OnlineStatus is the answer of a session validity probe.
type OnlineStatus struct {
	Username string
	Code     int
	Message  string
}

// CheckSavedOnline probes a saved session without logging in: it is what the
// GUI uses while a helper process owns the only live tunnel, so the user can
// still ask "is this login still mine?".
func CheckSavedOnline(server string, port int, clientData []byte) (OnlineStatus, error) {
	var cd auth.ClientAuthData
	if err := json.Unmarshal(clientData, &cd); err != nil {
		return OnlineStatus{}, fmt.Errorf("会话文件无法解析：%w", err)
	}
	if len(cd.Cookies) == 0 {
		return OnlineStatus{}, errors.New("会话文件里没有 cookie")
	}
	under, err := underlay.New(underlay.Options{AutoDetect: true})
	if err != nil {
		return OnlineStatus{}, fmt.Errorf("创建底层拨号器：%w", err)
	}
	defer func() { _ = under.Close() }()

	host := server
	if port != 0 && port != 443 {
		host = fmt.Sprintf("%s:%d", server, port)
	}
	sess := auth.NewSessionContext(context.Background(), host, nil, under.DialContext)
	sess.Restore(cd.DeviceID, "", cd.Cookies)
	username, code, message, err := sess.OnlineProbe()
	status := OnlineStatus{Username: username, Code: code, Message: message}
	if err != nil {
		return status, err
	}
	return status, nil
}

// CheckOnline asks the portal whether this session is still the active one.
// When another client logs in with the same account the server takes the
// session over, and the only way to notice is to ask.
func (c *Client) CheckOnline() (OnlineStatus, error) {
	c.sessionMu.RLock()
	data := c.authData
	c.sessionMu.RUnlock()
	if c.authHost == "" || len(data.Cookies) == 0 {
		return OnlineStatus{}, errors.New("没有可用于检测的会话")
	}
	sess := auth.NewSessionContext(c.lifecycleCtx, c.authHost, c.tlsKeyLogWriter, c.underlayDialer.DialContext)
	sess.Restore(data.DeviceID, "", data.Cookies)
	username, code, message, err := sess.OnlineProbe()
	status := OnlineStatus{Username: username, Code: code, Message: message}
	if err != nil {
		return status, err
	}
	return status, nil
}
