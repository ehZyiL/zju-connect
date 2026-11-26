package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// OnlineProbe asks the portal who is online with this session. Unlike the
// login-time call it hands the server code back, so a caller can tell
// "session taken over" apart from "network trouble".
func (s *Session) OnlineProbe() (username string, code int, message string, err error) {
	u := s.baseURL + "/passport/v1/user/onlineInfo"
	req, _ := http.NewRequest("GET", u+"?"+WithSharedParams(nil).Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return "", 0, "", err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return "", resp.StatusCode, "", readErr
	}

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Username string `json:"username"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &re); err != nil {
		return "", resp.StatusCode, "", fmt.Errorf("onlineInfo 响应无法解析：%w", err)
	}
	if resp.StatusCode != http.StatusOK && re.Code == 0 {
		return "", resp.StatusCode, re.Message, fmt.Errorf("onlineInfo HTTP %d", resp.StatusCode)
	}
	return re.Data.Username, re.Code, re.Message, nil
}

// ticketFromMap finds a portal ticket in an authConfig data object, avoiding
// the anti-MITM ticket, which is unrelated.
func ticketFromMap(data map[string]any) string {
	for _, key := range []string{"ticket", "loginTicket", "authTicket", "portalTicket", "sdpTicket"} {
		if v, ok := data[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
