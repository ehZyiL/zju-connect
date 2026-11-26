package auth

import (
	"encoding/json"
	"fmt"
	"strings"
)

type graphCheckCodePoint struct {
	X int `json:"x"`
	Y int `json:"y"`
}

func canonicalizeGraphCheckCode(raw string, imgData []byte) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("empty graph check code")
	}

	if payload, ok := parseGraphCheckCodeObject(trimmed); ok {
		if payload.Width <= 0 || payload.Height <= 0 {
			w, h, err := decodeImageSize(imgData)
			if err != nil {
				return "", fmt.Errorf("graph check code width/height missing and image size unavailable: %w", err)
			}
			payload.Width = w
			payload.Height = h
		}
		return marshalGraphCheckCode(payload)
	}

	if payload, ok := parseGraphCheckCodePointObjectArray(trimmed); ok {
		w, h, err := decodeImageSize(imgData)
		if err != nil {
			return "", fmt.Errorf("failed to decode captcha image size: %w", err)
		}
		payload.Width = w
		payload.Height = h
		return marshalGraphCheckCode(payload)
	}

	if payload, ok := parseGraphCheckCodeTupleArray(trimmed); ok {
		w, h, err := decodeImageSize(imgData)
		if err != nil {
			return "", fmt.Errorf("failed to decode captcha image size: %w", err)
		}
		payload.Width = w
		payload.Height = h
		return marshalGraphCheckCode(payload)
	}

	return "", fmt.Errorf("unsupported graph check code format")
}

func parseGraphCheckCodeObject(raw string) (graphCheckCodePayload, bool) {
	var payload graphCheckCodePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return graphCheckCodePayload{}, false
	}
	if !isValidCoordinates(payload.Coordinates) {
		return graphCheckCodePayload{}, false
	}
	return payload, true
}

func parseGraphCheckCodePointObjectArray(raw string) (graphCheckCodePayload, bool) {
	var points []graphCheckCodePoint
	if err := json.Unmarshal([]byte(raw), &points); err != nil {
		return graphCheckCodePayload{}, false
	}
	if len(points) == 0 {
		return graphCheckCodePayload{}, false
	}
	coordinates := make([][]int, 0, len(points))
	for _, p := range points {
		coordinates = append(coordinates, []int{p.X, p.Y})
	}
	if !isValidCoordinates(coordinates) {
		return graphCheckCodePayload{}, false
	}
	return graphCheckCodePayload{Coordinates: coordinates}, true
}

func parseGraphCheckCodeTupleArray(raw string) (graphCheckCodePayload, bool) {
	var coordinates [][]int
	if err := json.Unmarshal([]byte(raw), &coordinates); err != nil {
		return graphCheckCodePayload{}, false
	}
	if !isValidCoordinates(coordinates) {
		return graphCheckCodePayload{}, false
	}
	return graphCheckCodePayload{Coordinates: coordinates}, true
}
