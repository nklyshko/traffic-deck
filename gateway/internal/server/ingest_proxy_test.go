package server

import (
	"testing"

	trafficv1 "gitlab.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
)

// A pushed flow that rode a SOCKS/CONNECT proxy carries a Proxy field (mitmproxy's
// SocksUpstreamLayer stamps it). protoToDecodeFlow must copy it into the decode.Flow the
// store persists — nothing on the store side re-derives it, so dropping it here loses the
// proxy metadata for good (regression: it was silently omitted from the mapping).
func TestProtoToDecodeFlow_CarriesProxy(t *testing.T) {
	pf := &trafficv1.Flow{
		Id: "f1",
		Proxy: &trafficv1.Proxy{
			Addr: "socks-proxy.example:1080", Type: "socks",
			Username: "user", Password: "pass",
		},
	}
	df := protoToDecodeFlow(pf)
	if df.Proxy == nil {
		t.Fatal("Proxy dropped during ingest conversion")
	}
	if df.Proxy.Addr != "socks-proxy.example:1080" || df.Proxy.Type != "socks" ||
		df.Proxy.Username != "user" || df.Proxy.Password != "pass" {
		t.Fatalf("Proxy fields not carried faithfully: %+v", df.Proxy)
	}
}

// No proxy on the wire → no Proxy on the decode.Flow (not an empty non-nil struct).
func TestProtoToDecodeFlow_NoProxy(t *testing.T) {
	if df := protoToDecodeFlow(&trafficv1.Flow{Id: "f2"}); df.Proxy != nil {
		t.Fatalf("expected nil Proxy, got %+v", df.Proxy)
	}
}
