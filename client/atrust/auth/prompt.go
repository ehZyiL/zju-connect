package auth

import (
	"strings"
	"time"

	"github.com/mythologyli/zju-connect/client/authchallenge"
)

// CodePrompter is the Hub compatibility API. New embedders may supply a
// ChallengeHandler to handle every challenge through one interface.
type CodeKind int

const (
	CodeSMS CodeKind = iota
	CodeCustomSMS
	CodeTOTP
	CodeRADIUS
)

type CodeRequest struct {
	Kind CodeKind
	Tip  string
}

type CodePrompter func(CodeRequest) (string, error)

func (s *Session) handleCodeChallenge(challenge authchallenge.CodeChallenge, kind CodeKind) (authchallenge.CodeResponse, error) {
	if s.promptCode == nil {
		return s.challengeHandler.HandleCodeChallenge(challenge)
	}
	tip := ""
	if kind == CodeSMS || kind == CodeCustomSMS {
		tip = s.lastTip
	}
	code, err := s.promptCode(CodeRequest{Kind: kind, Tip: tip})
	if err != nil {
		return authchallenge.CodeResponse{}, err
	}
	skip := false
	if challenge.CanSkipSecondaryAuth {
		code, skip = strings.CutPrefix(code, "$")
	}
	return authchallenge.CodeResponse{Code: code, SkipSecondaryAuth: skip}, nil
}

func (s *Session) promptGraphCheckCode(image []byte, outputPath string) (string, error) {
	if s.browserCaptcha && outputPath == "" {
		return serveCaptchaInBrowser(s.ctx, image, 5*time.Minute)
	}
	response, err := s.challengeHandler.HandleClickCaptcha(authchallenge.ClickCaptchaChallenge{
		Image: image, OutputPath: outputPath, Message: "Please enter the graph check code JSON:",
	})
	if err != nil {
		return "", err
	}
	return graphCheckCodeFromResponse(response, image)
}
