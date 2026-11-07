package respcheck_test

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/ericfitz/agentmesh/internal/respcheck"
)

const specYAML = `
openapi: 3.0.3
info: {title: t, version: 1.0.0}
paths:
  /things/{id}:
    get:
      operationId: getThing
      parameters:
        - {name: id, in: path, required: true, schema: {type: string}}
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
                required: [ok]
                properties: {ok: {type: boolean}}
        "204": {description: none}
        "404":
          description: missing
          content:
            application/problem+json:
              schema:
                type: object
                required: [code]
                properties:
                  code: {type: string, enum: [not_found]}
        "429":
          description: slow down
          headers:
            Retry-After: {required: true, schema: {type: integer}}
          content:
            application/problem+json:
              schema: {type: object}
`

func loadDoc(t *testing.T) *openapi3.T {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromData([]byte(specYAML))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func newChecker(t *testing.T) *respcheck.Checker {
	t.Helper()
	c, err := respcheck.New(loadDoc(t))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func get(path string) *http.Request {
	return httptest.NewRequest(http.MethodGet, path, nil)
}

func TestCheck(t *testing.T) {
	problem := "application/problem+json"
	cases := []struct {
		name    string
		req     *http.Request
		status  int
		header  http.Header
		body    string
		wantErr []string // substrings; nil means success
		noRoute bool
	}{
		{name: "declared_ok", req: get("/things/a"), status: 200, header: hdr("Content-Type", "application/json"), body: `{"ok":true}`},
		{name: "undeclared_status", req: get("/things/a"), status: 500, header: hdr("Content-Type", problem), body: `{"code":"internal"}`, wantErr: []string{"500", "getThing"}},
		{name: "wrong_body", req: get("/things/a"), status: 404, header: hdr("Content-Type", problem), body: `{"code":"conflict"}`, wantErr: []string{"code"}},
		{name: "missing_header", req: get("/things/a"), status: 429, header: hdr("Content-Type", problem), body: `{}`, wantErr: []string{"Retry-After"}},
		{name: "wrong_content_type", req: get("/things/a"), status: 404, header: hdr("Content-Type", "application/json"), body: `{"code":"not_found"}`, wantErr: []string{"Content-Type"}},
		{name: "bodiless_204", req: get("/things/a"), status: 204, header: http.Header{}},
		{name: "no_route", req: httptest.NewRequest(http.MethodDelete, "/nothing", nil), status: 404, header: http.Header{}, noRoute: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newChecker(t)
			err := c.Check(tc.req, tc.status, tc.header, []byte(tc.body))
			switch {
			case tc.noRoute:
				if !errors.Is(err, respcheck.ErrNoRoute) || c.Skipped() != 1 {
					t.Fatalf("err = %v, skipped = %d; want ErrNoRoute and 1", err, c.Skipped())
				}
			case tc.wantErr == nil:
				if err != nil || c.Skipped() != 0 {
					t.Fatalf("err = %v, skipped = %d; want nil and 0", err, c.Skipped())
				}
			default:
				if err == nil {
					t.Fatal("want an error")
				}
				for _, s := range tc.wantErr {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("error %q lacks %q", err, s)
					}
				}
			}
		})
	}
}

type collector struct {
	mu   sync.Mutex
	errs []error
}

func (c *collector) report(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errs = append(c.errs, err)
}

func (c *collector) n() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.errs)
}

func TestTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodDelete:
			w.WriteHeader(404)
		case r.URL.Path == "/things/bad":
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(500)
			_, _ = io.WriteString(w, `{"code":"internal"}`)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		}
	}))
	defer srv.Close()
	c := newChecker(t)
	var col collector
	cl := &http.Client{Transport: c.Transport(http.DefaultTransport, col.report)}

	t.Run("transport_restores_body", func(t *testing.T) {
		resp, err := cl.Get(srv.URL + "/things/a")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(b) != `{"ok":true}` || col.n() != 0 {
			t.Fatalf("body %q, reports %d", b, col.n())
		}
	})
	t.Run("violation_reported_response_unchanged", func(t *testing.T) {
		resp, err := cl.Get(srv.URL + "/things/bad")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 500 || string(b) != `{"code":"internal"}` || col.n() != 1 {
			t.Fatalf("status %d body %q reports %d", resp.StatusCode, b, col.n())
		}
	})
	t.Run("no_route_not_reported", func(t *testing.T) {
		before := col.n()
		req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/nothing", nil)
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if col.n() != before || c.Skipped() != 1 {
			t.Fatalf("reports %d (was %d), skipped %d", col.n(), before, c.Skipped())
		}
	})
}

func TestProxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/things/bad":
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(500)
			_, _ = io.WriteString(w, `{"code":"internal"}`)
		case "/things/none":
			w.WriteHeader(204)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true,"host":"`+r.Host+`"}`)
		}
	}))
	defer target.Close()
	tu, _ := url.Parse(target.URL)
	c := newChecker(t)
	var col collector
	px := httptest.NewServer(c.Proxy(tu, col.report))
	defer px.Close()
	pu, _ := url.Parse(px.URL)

	t.Run("proxy_keeps_host", func(t *testing.T) {
		resp, err := http.Get(px.URL + "/things/a")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if !strings.Contains(string(b), `"host":"`+pu.Host+`"`) || strings.Contains(string(b), tu.Host) {
			t.Fatalf("body %s: host is not the proxy's %s", b, pu.Host)
		}
		if col.n() != 0 {
			t.Fatalf("unexpected reports: %v", col.errs)
		}
	})
	t.Run("proxy_reports_violation", func(t *testing.T) {
		resp, err := http.Get(px.URL + "/things/bad")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 500 || col.n() != 1 {
			t.Fatalf("status %d reports %d", resp.StatusCode, col.n())
		}
	})
	t.Run("proxy_streams_bodiless", func(t *testing.T) {
		before := col.n()
		resp, err := http.Get(px.URL + "/things/none")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 204 || col.n() != before {
			t.Fatalf("status %d reports %d (was %d)", resp.StatusCode, col.n(), before)
		}
	})
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, errors.New("boom") }
func (errBody) Close() error             { return nil }

func TestTransportEdges(t *testing.T) {
	c := newChecker(t)
	var col collector
	mk := func(resp *http.Response) *http.Client {
		return &http.Client{Transport: c.Transport(rtFunc(func(*http.Request) (*http.Response, error) { return resp, nil }), col.report)}
	}
	t.Run("nil_body", func(t *testing.T) {
		resp, err := mk(&http.Response{StatusCode: 204, Header: http.Header{}}).Get("http://x/things/a")
		if err != nil {
			t.Fatal(err)
		}
		if resp.Body == nil || col.n() != 0 {
			t.Fatalf("body %v reports %d", resp.Body, col.n())
		}
	})
	t.Run("read_error", func(t *testing.T) {
		resp, err := mk(&http.Response{StatusCode: 200, Header: http.Header{}, Body: errBody{}}).Get("http://x/things/a")
		if err == nil || !strings.Contains(err.Error(), "boom") || resp != nil {
			t.Fatalf("resp %v err %v", resp, err)
		}
	})
}

func TestProxyGzipClient(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			_, _ = zw.Write([]byte(`{"ok":true}`))
			_ = zw.Close()
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()
	tu, _ := url.Parse(target.URL)
	var col collector
	px := httptest.NewServer(newChecker(t).Proxy(tu, col.report))
	defer px.Close()
	req, _ := http.NewRequest(http.MethodGet, px.URL+"/things/a", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(b) != `{"ok":true}` || col.n() != 0 {
		t.Fatalf("body %q reports %v", b, col.errs)
	}
}

func TestProxyReadErrorReported(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok"`)) // short body: the connection closes early
	}))
	defer target.Close()
	tu, _ := url.Parse(target.URL)
	var col collector
	px := httptest.NewServer(newChecker(t).Proxy(tu, col.report))
	defer px.Close()
	resp, err := http.Get(px.URL + "/things/a")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || col.n() != 1 || !strings.Contains(col.errs[0].Error(), "could not read") {
		t.Fatalf("status %d reports %v", resp.StatusCode, col.errs)
	}
}

func TestCheckConcurrent(t *testing.T) {
	c := newChecker(t)
	var bad atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if err := c.Check(get(fmt.Sprintf("/things/%d", j)), 200, hdr("Content-Type", "application/json"), []byte(`{"ok":true}`)); err != nil {
					bad.Add(1)
				}
				if err := c.Check(get("/things/a"), 500, http.Header{}, nil); err == nil {
					bad.Add(1)
				}
				_ = c.Check(httptest.NewRequest(http.MethodDelete, "/nothing", nil), 404, http.Header{}, nil)
			}
		}(i)
	}
	wg.Wait()
	if bad.Load() != 0 || c.Skipped() != 32*20 {
		t.Fatalf("bad %d skipped %d", bad.Load(), c.Skipped())
	}
}
