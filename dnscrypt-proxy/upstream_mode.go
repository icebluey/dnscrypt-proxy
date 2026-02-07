package main

import "strings"

type UpstreamMode string

const (
	UpstreamModeParallel UpstreamMode = "parallel"
)

func parseUpstreamMode(raw string) (UpstreamMode, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", true
	case string(UpstreamModeParallel):
		return UpstreamModeParallel, true
	default:
		return "", false
	}
}
