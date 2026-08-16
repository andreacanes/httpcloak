package transport

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// h1CaptureServer is a raw TCP listener that reads the literal request block a
// client writes. Plain http:// has no ALPN and no TLS, so the bytes that arrive
// ARE the bytes sent — this reads the wire rather than asking the library what
// it thinks it sent.
type h1CaptureServer struct {
	addr   string
	orders chan []string
	ln     net.Listener
	closed chan struct{}
}

func startH1CaptureServer(t *testing.T) *h1CaptureServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &h1CaptureServer{
		addr:   ln.Addr().String(),
		orders: make(chan []string, 64),
		ln:     ln,
		closed: make(chan struct{}),
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleConn(c)
		}
	}()
	t.Cleanup(func() {
		close(s.closed)
		_ = ln.Close()
	})
	return s
}

func (s *h1CaptureServer) handleConn(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		// Request line.
		if _, err := br.ReadString('\n'); err != nil {
			return
		}
		var names []string
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			if i := strings.IndexByte(line, ':'); i > 0 {
				names = append(names, strings.ToLower(line[:i]))
			}
		}
		select {
		case s.orders <- names:
		default:
		}
		if _, err := io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"); err != nil {
			return
		}
	}
}

// h1WireOrders drives n identical requests through the real HTTP1Transport and
// returns the header-name order that arrived on the wire for each.
func h1WireOrders(t *testing.T, preset *fingerprint.Preset, customOrder []string, n int) [][]string {
	t.Helper()
	srv := startH1CaptureServer(t)
	url := "http://" + srv.addr + "/api/v1/quote"

	tr := NewHTTP1Transport(preset, dns.NewCache())
	defer tr.Close()

	userHeaders := map[string][]string{
		"Accept":       {"application/json"},
		"X-Api-Key":    {"k"},
		"Content-Type": {"application/json"},
	}

	var got [][]string
	for i := 0; i < n; i++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		for k, vs := range userHeaders {
			for _, v := range vs {
				req.Header.Set(k, v)
			}
		}
		applyPresetHeaders(req, newPresetWireHeaders(preset), customOrder, nil, false, "h1", userHeaders, false, nil)

		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip %d: %v", i, err)
		}
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		select {
		case order := <-srv.orders:
			got = append(got, order)
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for capture %d", i)
		}
	}
	return got
}

func assertIdenticalOrders(t *testing.T, label string, orders [][]string) {
	t.Helper()
	distinct := map[string][]string{}
	for _, o := range orders {
		distinct[strings.Join(o, ",")] = o
	}
	if len(distinct) != 1 {
		t.Errorf("%s: %d identical requests transmitted %d DISTINCT header orders — the fingerprint changes per request",
			label, len(orders), len(distinct))
		i := 0
		for _, o := range distinct {
			t.Logf("  order %d: %s", i, strings.Join(o, " "))
			i++
		}
	}
}

// TestH1TransmittedHeaderOrderIsDeterministic pins F22 for HTTP/1.1: the
// injected header tail (everything the preset adds beyond the caller's defined
// order) used to be emitted from Go map iteration, so six identical requests
// transmitted six distinct orders. A cloaking transport whose fingerprint
// changes every request is worse than a consistent one.
//
// PASS CRITERION: byte-identical transmitted order across N identical requests.
func TestH1TransmittedHeaderOrderIsDeterministic(t *testing.T) {
	preset := fingerprint.Get("chrome-147-windows")
	if preset == nil {
		t.Skip("chrome-147-windows preset unavailable")
	}
	// A short caller-defined order, exactly like a consumer that pins the few
	// headers it cares about: everything else lands in the injected tail.
	customOrder := []string{"user-agent", "accept", "content-type"}
	orders := h1WireOrders(t, preset, customOrder, 6)
	assertIdenticalOrders(t, "h1 custom-order tail", orders)
}

// TestH1TransmittedHeaderOrderIsDeterministic_PresetOrder covers the other
// production shape: no custom order, so the preset's own H2HeaderOrder drives
// placement and the tail is whatever the preset order does not name.
func TestH1TransmittedHeaderOrderIsDeterministic_PresetOrder(t *testing.T) {
	preset := fingerprint.Get("chrome-147-windows")
	if preset == nil {
		t.Skip("chrome-147-windows preset unavailable")
	}
	orders := h1WireOrders(t, preset, nil, 6)
	assertIdenticalOrders(t, "h1 preset-order tail", orders)
}

// h2WireOrders drives n identical requests through the real HTTP2Transport and
// returns the header-name order the HPACK decoder emitted for each — HPACK
// fields arrive in wire order, so this reads the wire too.
func h2WireOrders(t *testing.T, preset *fingerprint.Preset, customOrder []string, n int) [][]string {
	t.Helper()
	srv := startH2CaptureServer(t)
	host, port, _ := net.SplitHostPort(srv.addr)
	url := "https://" + net.JoinHostPort(host, port) + "/api/v1/quote"

	tr := NewHTTP2Transport(preset, dns.NewCache())
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	userHeaders := map[string][]string{
		"Accept":       {"application/json"},
		"X-Api-Key":    {"k"},
		"Content-Type": {"application/json"},
	}

	var got [][]string
	for i := 0; i < n; i++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		for k, vs := range userHeaders {
			for _, v := range vs {
				req.Header.Set(k, v)
			}
		}
		applyPresetHeaders(req, newPresetWireHeaders(preset), customOrder, nil, false, "h2", userHeaders, false, nil)

		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip %d: %v", i, err)
		}
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		select {
		case c := <-srv.captures:
			got = append(got, c.HeaderOrder)
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for capture %d", i)
		}
	}
	return got
}

// TestH2TransmittedHeaderOrderIsDeterministic is the H2 half of the F22 pass
// criterion. The H2 writer already ranks its tail through a total-order sorter
// rather than map iteration; this pins that so it cannot regress into the H1
// failure mode, and holds the two protocols to the same guarantee.
func TestH2TransmittedHeaderOrderIsDeterministic(t *testing.T) {
	preset := fingerprint.Get("chrome-147-windows")
	if preset == nil {
		t.Skip("chrome-147-windows preset unavailable")
	}
	customOrder := []string{"user-agent", "accept", "content-type"}
	orders := h2WireOrders(t, preset, customOrder, 6)
	assertIdenticalOrders(t, "h2 custom-order tail", orders)
	t.Logf("h2 transmitted order: %s", strings.Join(orders[0], " "))
}

// TestConsumerDeclaredOrderIsTransmittedVerbatim pins the downstream contract.
// FUCKBOT-go applies a per-request lowercase order via SetHeaderOrder and its
// offline oracle diffs the outgoing order POSITIONALLY, so the fix must leave
// every header the consumer named exactly where the consumer put it and only
// make the injected tail deterministic. The order below is FUCKBOT-go's
// engine/retailers/apple navigationHeaderOrder, verbatim.
func TestConsumerDeclaredOrderIsTransmittedVerbatim(t *testing.T) {
	preset := fingerprint.Get("chrome-147-windows")
	if preset == nil {
		t.Skip("chrome-147-windows preset unavailable")
	}
	declared := []string{
		"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests",
		"user-agent", "accept", "true-client-ip", "sec-fetch-site", "sec-fetch-mode",
		"sec-fetch-user", "sec-fetch-dest", "referer", "accept-encoding", "accept-language",
		"cookie", "priority",
	}

	for _, tc := range []struct {
		name  string
		wire  func(*testing.T, *fingerprint.Preset, []string, int) [][]string
		strip int // leading pseudo-headers to skip
	}{
		{"h1", h1WireOrders, 0},
		{"h2", h2WireOrders, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orders := tc.wire(t, preset, declared, 4)
			assertIdenticalOrders(t, tc.name+" consumer order", orders)

			got := orders[0][tc.strip:]
			if tc.name == "h1" {
				// H1 writes Host and Connection ahead of the declared list.
				for len(got) > 0 && (got[0] == "host" || got[0] == "connection") {
					got = got[1:]
				}
			}
			// Every declared header that is actually present must appear in the
			// declared relative order, before anything undeclared.
			di := 0
			for i, name := range got {
				for di < len(declared) && declared[di] != name {
					di++
				}
				if di == len(declared) {
					// First undeclared header: the tail starts here. Nothing
					// after it may be a declared name.
					for _, rest := range got[i:] {
						for _, d := range declared {
							if rest == d {
								t.Fatalf("declared header %q was emitted in the tail, after undeclared headers: %s",
									rest, strings.Join(got, " "))
							}
						}
					}
					break
				}
			}
			t.Logf("%s transmitted: %s", tc.name, strings.Join(orders[0], " "))
		})
	}
}
