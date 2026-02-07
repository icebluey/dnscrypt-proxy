package main

import "testing"

func TestParseUpstreamMode(t *testing.T) {
	tests := []struct {
		in         string
		wantMode   UpstreamMode
		wantParsed bool
	}{
		{in: "", wantMode: "", wantParsed: true},
		{in: "parallel", wantMode: UpstreamModeParallel, wantParsed: true},
		{in: "PARALLEL", wantMode: UpstreamModeParallel, wantParsed: true},
		{in: " load_balance ", wantMode: "", wantParsed: false},
		{in: "random", wantMode: "", wantParsed: false},
	}

	for _, tc := range tests {
		gotMode, gotParsed := parseUpstreamMode(tc.in)
		if gotMode != tc.wantMode || gotParsed != tc.wantParsed {
			t.Fatalf("parseUpstreamMode(%q) = (%q, %v), want (%q, %v)", tc.in, gotMode, gotParsed, tc.wantMode, tc.wantParsed)
		}
	}
}
