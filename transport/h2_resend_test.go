package transport

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/net/http2"
	"github.com/sardanioss/net/http2/hpack"
)

// h2FaultServer is an HTTP/2-over-TLS listener that counts the HEADERS frames
// that actually reach it and lets each connection be faulted independently. It
// answers the only question that matters for F21: how many requests hit the
// socket for ONE logical call through our layer.
type h2FaultServer struct {
	addr string

	// headersSeen counts request HEADERS frames read off the wire, across all
	// connections. This is the "requests that reached the socket" number.
	headersSeen atomic.Int32
	connsSeen   atomic.Int32
	// h1RequestsSeen counts requests that arrived on a connection that
	// negotiated HTTP/1.1.
	h1RequestsSeen atomic.Int32

	mu     sync.Mutex
	orders [][]string

	// fault decides what a connection does, given its 1-based index.
	fault func(connIndex int32) h2Fault
}

type h2Fault int

const (
	// h2FaultNone serves a normal 200.
	h2FaultNone h2Fault = iota
	// h2FaultBreakAfterHeaders reads the request — so the server HAS seen and
	// could have processed it — then drops the TCP connection without
	// responding. The client cannot know whether it was processed.
	h2FaultBreakAfterHeaders
	// h2FaultGoAwayUnprocessed sends GOAWAY(LastStreamID=0, NO_ERROR) before
	// serving anything, which is the server declaring on the wire that it
	// processed no stream on this connection.
	h2FaultGoAwayUnprocessed
	// h2FaultResetStream reads the request, then resets its stream with
	// INTERNAL_ERROR, as an edge does to a login POST it refuses to serve.
	h2FaultResetStream
)

func startH2FaultServer(t *testing.T, fault func(connIndex int32) h2Fault) *h2FaultServer {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(crand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("certgen: %v", err)
	}
	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	cert, err := stdtls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}),
	)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", &stdtls.Config{
		Certificates: []stdtls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   stdtls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &h2FaultServer{addr: ln.Addr().String(), fault: fault}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleConn(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *h2FaultServer) handleConn(c net.Conn) {
	defer c.Close()
	idx := s.connsSeen.Add(1)
	fault := s.fault(idx)

	tc, ok := c.(*stdtls.Conn)
	if !ok {
		return
	}
	if err := tc.Handshake(); err != nil {
		return
	}
	if tc.ConnectionState().NegotiatedProtocol != "h2" {
		s.serveHTTP1(c)
		return
	}
	preface := make([]byte, len(h2PrefaceStr))
	if _, err := io.ReadFull(c, preface); err != nil || string(preface) != h2PrefaceStr {
		return
	}

	fr := http2.NewFramer(c, c)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		return
	}

	if fault == h2FaultGoAwayUnprocessed {
		// LastStreamID=0 with NO_ERROR: "I processed nothing on this
		// connection." Every stream above 0 is provably not processed.
		_ = fr.WriteGoAway(0, http2.ErrCodeNo, nil)
		return
	}

	var encBuf strings.Builder
	enc := hpack.NewEncoder(&encBuf)

	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.MetaHeadersFrame:
			s.headersSeen.Add(1)
			order := make([]string, 0, len(f.Fields))
			for _, hf := range f.Fields {
				order = append(order, hf.Name)
			}
			s.mu.Lock()
			s.orders = append(s.orders, order)
			s.mu.Unlock()

			if fault == h2FaultResetStream {
				_ = fr.WriteRSTStream(f.StreamID, http2.ErrCodeInternal)
				continue
			}
			if fault == h2FaultBreakAfterHeaders {
				// The request is in. Drop the connection without answering:
				// the client cannot tell processed from not-processed.
				return
			}
			encBuf.Reset()
			_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			_ = enc.WriteField(hpack.HeaderField{Name: "content-length", Value: "0"})
			_ = fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      f.StreamID,
				BlockFragment: []byte(encBuf.String()),
				EndHeaders:    true,
				EndStream:     true,
			})
		}
	}
}

// serveHTTP1 answers one request on an HTTP/1.1 connection and counts it.
func (s *h2FaultServer) serveHTTP1(c net.Conn) {
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" {
			break
		}
	}
	s.h1RequestsSeen.Add(1)
	_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
}

func h2FaultRequest(t *testing.T, tr *HTTP2Transport, preset *fingerprint.Preset, addr string) (*http.Response, error) {
	t.Helper()
	host, port, _ := net.SplitHostPort(addr)
	req, err := http.NewRequest("POST", "https://"+net.JoinHostPort(host, port)+"/orders", strings.NewReader(`{"qty":1}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	uh := map[string][]string{"Content-Type": {"application/json"}}
	req.Header.Set("Content-Type", "application/json")
	applyPresetHeaders(req, newPresetWireHeaders(preset), nil, nil, false, "h2", uh, false, nil)
	return tr.RoundTrip(req)
}

// TestH2DoesNotResendAfterMaybeProcessedError is the F21 money-safety
// invariant. The H2 transport used to drop the connection and re-RoundTrip
// after ANY error, beneath both WithoutRetry() and the caller's Sender seam, so
// ONE logical call put TWO requests on the wire — a hidden double-submit of a
// non-idempotent write that no injected-Sender test could see.
//
// The server here reads the request and then breaks the connection: it HAS the
// request and may have acted on it. The transport must surface that error, not
// silently send the order again.
func TestH2DoesNotResendAfterMaybeProcessedError(t *testing.T) {
	preset := fingerprint.Get("chrome-147-windows")
	if preset == nil {
		t.Skip("chrome-147-windows preset unavailable")
	}
	srv := startH2FaultServer(t, func(int32) h2Fault { return h2FaultBreakAfterHeaders })

	tr := NewHTTP2Transport(preset, dns.NewCache())
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	resp, err := h2FaultRequest(t, tr, preset, srv.addr)
	if err == nil {
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		t.Fatalf("expected the maybe-processed fault to surface as an error")
	}
	if n := srv.headersSeen.Load(); n != 1 {
		t.Errorf("ONE logical call put %d request(s) on the wire over %d connection(s) — a maybe-processed error must never be resent beneath the Sender seam",
			n, srv.connsSeen.Load())
	}
}

// TestH2ResendsAfterProvablyNotProcessedError is the other half of the rule:
// when the server declares on the wire that it processed nothing (GOAWAY with
// LastStreamID below this stream), a transparent resend cannot double-submit,
// so the call must still succeed rather than surfacing a spurious failure.
func TestH2ResendsAfterProvablyNotProcessedError(t *testing.T) {
	preset := fingerprint.Get("chrome-147-windows")
	if preset == nil {
		t.Skip("chrome-147-windows preset unavailable")
	}
	// First connection declares "nothing processed"; the retry connection serves.
	srv := startH2FaultServer(t, func(i int32) h2Fault {
		if i == 1 {
			return h2FaultGoAwayUnprocessed
		}
		return h2FaultNone
	})

	tr := NewHTTP2Transport(preset, dns.NewCache())
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()

	resp, err := h2FaultRequest(t, tr, preset, srv.addr)
	if err != nil {
		t.Fatalf("a provably-not-processed error must be transparently resent, got: %v", err)
	}
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if n := srv.headersSeen.Load(); n != 1 {
		t.Errorf("server processed %d requests, want exactly 1", n)
	}
}
