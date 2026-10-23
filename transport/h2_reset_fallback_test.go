package transport

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// startConnectProxy runs an HTTP CONNECT proxy that tunnels to target. It
// refuses the first refuse CONNECTs with 502 and returns how many it has seen.
func startConnectProxy(t *testing.T, target string, refuse int32) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	connects := new(atomic.Int32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				if connects.Add(1) <= refuse {
					_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
					return
				}
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close()
				_, _ = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				go func() { _, _ = io.Copy(up, br); _ = up.Close() }()
				_, _ = io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String(), connects
}

func doProxiedPOST(t *testing.T, srv *h2FaultServer, refuseConnects int32) (*Response, error) {
	t.Helper()
	proxy, _ := startConnectProxy(t, srv.addr, refuseConnects)
	tr := NewTransportWithConfig("chrome-146", &ProxyConfig{URL: "http://" + proxy}, nil)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()
	return tr.Do(context.Background(), &Request{
		Method:  "POST",
		URL:     "https://" + srv.addr + "/identity/authenticate",
		Body:    []byte(`{"qty":1}`),
		Timeout: 10 * time.Second,
	})
}

// A POST whose HTTP/2 stream the server reset after reading it may have been
// acted on, so auto mode through an HTTP proxy must return the stream error
// rather than send the POST again on a new HTTP/1.1 connection.
func TestAutoHTTPProxyDoesNotResendPOSTOnH1AfterStreamReset(t *testing.T) {
	srv := startH2FaultServer(t, func(int32) h2Fault { return h2FaultResetStream })

	resp, err := doProxiedPOST(t, srv, 0)
	if err == nil {
		t.Fatalf("expected the stream reset to surface, got status %d", resp.StatusCode)
	}
	if n := srv.headersSeen.Load(); n != 1 {
		t.Errorf("h2 requests = %d, want 1", n)
	}
	if n := srv.h1RequestsSeen.Load(); n != 0 {
		t.Errorf("the POST was sent again on HTTP/1.1 %d time(s)", n)
	}
}

// When the HTTP/2 attempt fails before anything is sent, a POST still falls
// back to HTTP/1.1. The proxy refuses the two tunnels the HTTP/2 dialer tries
// and opens the third for HTTP/1.1.
func TestAutoHTTPProxyFallsBackToH1WhenNothingWasSent(t *testing.T) {
	srv := startH2FaultServer(t, func(int32) h2Fault { return h2FaultNone })

	resp, err := doProxiedPOST(t, srv, 2)
	if err != nil {
		t.Fatalf("a POST that was never sent must fall back to HTTP/1.1: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if n := srv.headersSeen.Load(); n != 0 {
		t.Errorf("h2 requests = %d, want 0", n)
	}
	if n := srv.h1RequestsSeen.Load(); n != 1 {
		t.Errorf("HTTP/1.1 requests = %d, want 1", n)
	}
}
