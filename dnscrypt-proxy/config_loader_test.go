package main

import (
	"crypto/tls"
	"testing"
)

func TestConfigureXTransportTLSDefaults(t *testing.T) {
	config := newConfig()

	proxy := Proxy{ // minimum wiring required for configureXTransport
		xTransport: NewXTransport(),
		mainProto:  "doh",
	}

	if err := configureXTransport(&proxy, &config); err != nil {
		t.Fatalf("configureXTransport returned error: %v", err)
	}

	if proxy.xTransport.tlsMinVersion != tls.VersionTLS13 {
		t.Fatalf("expected default min TLS version 1.3, got %v", proxy.xTransport.tlsMinVersion)
	}
	if proxy.xTransport.tlsMaxVersion != tls.VersionTLS13 {
		t.Fatalf("expected default max TLS version 1.3, got %v", proxy.xTransport.tlsMaxVersion)
	}
}

func TestConfigureXTransportTLSCustomRange(t *testing.T) {
	config := newConfig()
	config.HTTP3 = true
	config.HTTP3Probe = true
	config.TLSMinVersion = "1.2"
	config.TLSMaxVersion = "1.2"

	proxy := Proxy{
		xTransport: NewXTransport(),
		mainProto:  "doh",
	}

	if err := configureXTransport(&proxy, &config); err != nil {
		t.Fatalf("configureXTransport returned error: %v", err)
	}

	if proxy.xTransport.tlsMinVersion != tls.VersionTLS12 {
		t.Fatalf("expected min TLS version 1.2, got %v", proxy.xTransport.tlsMinVersion)
	}
	if proxy.xTransport.tlsMaxVersion != tls.VersionTLS12 {
		t.Fatalf("expected max TLS version 1.2, got %v", proxy.xTransport.tlsMaxVersion)
	}
	if proxy.xTransport.http3 || proxy.xTransport.http3Probe {
		t.Fatalf("HTTP/3 should be disabled when TLS max version is below 1.3")
	}
}
