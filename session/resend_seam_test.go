package session

import (
	"context"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
	"github.com/sardanioss/net/http2"
	"github.com/sardanioss/net/http2/hpack"
)

const seamPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// startBreakAfterHeadersServer serves HTTP/2 over TLS, counts the request
// HEADERS frames that actually arrive, and then drops each connection without
// answering. The server HAS the request and may have acted on it — the client
// cannot distinguish processed from not-processed, which is exactly the state a
// non-idempotent write must never be replayed from.
func startBreakAfterHeadersServer(t *testing.T) (addr string, headersSeen *atomic.Int32) {
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
		NextProtos:   []string{"h2"},
		MinVersion:   stdtls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	seen := &atomic.Int32{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc, ok := c.(*stdtls.Conn)
				if !ok {
					return
				}
				if err := tc.Handshake(); err != nil {
					return
				}
				preface := make([]byte, len(seamPreface))
				if _, err := io.ReadFull(c, preface); err != nil || string(preface) != seamPreface {
					return
				}
				fr := http2.NewFramer(c, c)
				fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
				if err := fr.WriteSettings(); err != nil {
					return
				}
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
						seen.Add(1)
						return // request in, connection dropped, no response
					}
				}
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), seen
}

// TestWithoutRetryPutsOneRequestOnTheWireOverH2 pins the F21 seam end to end.
// The H2 transport used to drop the connection and resend after ANY RoundTrip
// error — beneath a session configured for no retries, and beneath any injected
// Sender above it — so a caller that had explicitly disabled retries still put
// two POSTs on the wire. This drives a real Session and counts what reached the
// socket.
func TestWithoutRetryPutsOneRequestOnTheWireOverH2(t *testing.T) {
	addr, headersSeen := startBreakAfterHeadersServer(t)

	sess := NewSession("seam-f21", &protocol.SessionConfig{
		Preset:             "chrome-147-windows",
		ForceHTTP2:         true,
		InsecureSkipVerify: true,
		RetryEnabled:       false, // what WithoutRetry() sets
		Timeout:            10000,
	})
	defer sess.Close()

	resp, err := sess.Request(context.Background(), &transport.Request{
		Method:     "POST",
		URL:        "https://" + addr + "/orders",
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		BodyReader: strings.NewReader(`{"qty":1}`),
	})
	if err == nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		t.Fatalf("expected the maybe-processed fault to surface as an error")
	}
	if n := headersSeen.Load(); n != 1 {
		t.Errorf("no-retry session: ONE logical call put %d request(s) on the wire — the transport resent a non-idempotent write beneath the seam", n)
	}
}
