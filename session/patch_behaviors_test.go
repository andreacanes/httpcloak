package session

import (
	"context"
	"strings"
	"testing"

	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/httpcloak/transport"
)

// These tests pin the two fork-local behaviors that survive the merge-forward
// to upstream v1.6.8:
//
//  1. The GET/HEAD gate on conditional-cache validators (fork patch 2fa139e,
//     re-applied on top of upstream's conditionalCacheEnabled / per-request
//     DisableConditionalCache knobs). Sending If-None-Match / If-Modified-Since
//     on a POST is an anti-bot tell (Apple Shield edge-rejects it with 412); the
//     gate must never let a non-idempotent method carry those headers.
//  2. WithoutCookieJar (adopted from upstream, surface-identical to the fork's
//     original patch) actually suppresses jar injection into outgoing requests.
//
// probe drives the REAL requestWithRedirects gate logic. It passes
// redirectCount=1 so the function skips its hop-0 header clone and mutates the
// caller's req.Headers in place, and an already-canceled context so the
// transport call returns immediately — every session-layer header mutation
// (cache validators, cookies) has already run by the time transport.Do is
// reached. The 127.0.0.1:1 target is a belt-and-suspenders instant refuse.
const probeURL = "https://127.0.0.1:1/probe"

func probe(t *testing.T, cfg *protocol.SessionConfig, seed func(*Session), req *transport.Request) *transport.Request {
	t.Helper()
	if cfg == nil {
		cfg = &protocol.SessionConfig{}
	}
	s := NewSession("test", cfg)
	if s.transport == nil {
		t.Fatal("session has nil transport")
	}
	if seed != nil {
		seed(s)
	}
	if req.Headers == nil {
		req.Headers = map[string][]string{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = s.requestWithRedirects(ctx, req, 1, nil)
	return req
}

func TestConditionalCacheGatedByMethod(t *testing.T) {
	seed := func(s *Session) {
		s.cacheEntries[probeURL] = &cacheEntry{
			etag:         `"etag-xyz"`,
			lastModified: "Wed, 21 Oct 2026 07:28:00 GMT",
		}
	}

	// GET: the seeded validators ARE injected (browser-correct revalidation).
	get := probe(t, nil, seed, &transport.Request{Method: "GET", URL: probeURL})
	if got := get.Headers["If-None-Match"]; len(got) != 1 || got[0] != `"etag-xyz"` {
		t.Fatalf("GET: want If-None-Match [\"etag-xyz\"], got %v", get.Headers["If-None-Match"])
	}
	if len(get.Headers["If-Modified-Since"]) != 1 {
		t.Fatalf("GET: want If-Modified-Since injected, got %v", get.Headers["If-Modified-Since"])
	}

	// POST: the same seeded validators are NOT injected (the anti-bot gate).
	post := probe(t, nil, seed, &transport.Request{Method: "POST", URL: probeURL})
	if got := post.Headers["If-None-Match"]; len(got) != 0 {
		t.Fatalf("POST: If-None-Match leaked (anti-bot regression), got %v", got)
	}
	if got := post.Headers["If-Modified-Since"]; len(got) != 0 {
		t.Fatalf("POST: If-Modified-Since leaked (anti-bot regression), got %v", got)
	}
}

func TestConditionalCacheDisableKnobsIntact(t *testing.T) {
	seed := func(s *Session) {
		s.cacheEntries[probeURL] = &cacheEntry{etag: `"etag-xyz"`}
	}

	// Upstream per-request opt-out: even a GET is suppressed.
	req := probe(t, nil, seed, &transport.Request{
		Method: "GET", URL: probeURL, DisableConditionalCache: true,
	})
	if got := req.Headers["If-None-Match"]; len(got) != 0 {
		t.Fatalf("DisableConditionalCache: If-None-Match should be suppressed, got %v", got)
	}

	// Upstream session-wide opt-out flips conditionalCacheEnabled off.
	s := NewSession("test", &protocol.SessionConfig{WithoutConditionalCache: true})
	if s.conditionalCacheEnabled {
		t.Fatal("WithoutConditionalCache=true should init conditionalCacheEnabled=false")
	}
}

func TestWithoutCookieJarSuppressesInjection(t *testing.T) {
	seed := func(s *Session) {
		s.cookies.SetSimple("sid", "abc123", "127.0.0.1", "/", true, false, "Lax", 0, nil)
	}

	// Jar ON (default): the seeded cookie IS injected into the request.
	on := probe(t, &protocol.SessionConfig{}, seed, &transport.Request{Method: "GET", URL: probeURL})
	if got := on.Headers["Cookie"]; len(got) == 0 || !strings.Contains(got[0], "sid=abc123") {
		t.Fatalf("jar ON: want cookie injected, got %v", on.Headers["Cookie"])
	}

	// Jar OFF: the seeded cookie is NOT injected (WithoutCookieJar behavior).
	off := probe(t, &protocol.SessionConfig{WithoutCookieJar: true}, seed, &transport.Request{Method: "GET", URL: probeURL})
	if got := off.Headers["Cookie"]; len(got) != 0 {
		t.Fatalf("jar OFF: cookie leaked into request, got %v", got)
	}
}
