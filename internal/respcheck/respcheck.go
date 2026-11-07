package respcheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

// ErrNoRoute reports a request that matches no operation of the document (an
// unknown path, a method the document does not declare). It is not a
// violation: the checker counts it (Skipped) and Transport and Proxy do not
// report it.
var ErrNoRoute = errors.New("respcheck: no operation matches the request")

// Checker validates responses against one document. It is safe for concurrent
// use.
type Checker struct {
	router  routers.Router
	skipped atomic.Int64
}

// New builds a Checker over doc. A document with no servers matches any host.
func New(doc *openapi3.T) (*Checker, error) {
	r, err := gorillamux.NewRouter(doc)
	if err != nil {
		return nil, fmt.Errorf("respcheck: build router: %w", err)
	}
	return &Checker{router: r}, nil
}

// Check validates one response (status, header, body) to req. It returns
// ErrNoRoute (counted) when req matches no operation, else the validation
// error naming method, path, operationId, status and the reason, else nil.
func (c *Checker) Check(req *http.Request, status int, header http.Header, body []byte) error {
	route, pathParams, err := c.router.FindRoute(req)
	if err != nil {
		c.skipped.Add(1)
		return fmt.Errorf("%w: %s %s: %v", ErrNoRoute, req.Method, req.URL.Path, err)
	}
	in := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request:    req,
			PathParams: pathParams,
			Route:      route,
		},
		Status:  status,
		Header:  header,
		Options: &openapi3filter.Options{IncludeResponseStatus: true},
	}
	in.SetBodyBytes(body)
	if err := openapi3filter.ValidateResponse(context.Background(), in); err != nil {
		opID := ""
		if route.Operation != nil {
			opID = route.Operation.OperationID
		}
		return fmt.Errorf("respcheck: %s %s (operation %q) answered %d: %w", req.Method, req.URL.Path, opID, status, err)
	}
	return nil
}

// Skipped is the number of responses whose request matched no operation.
func (c *Checker) Skipped() int64 { return c.skipped.Load() }

// Transport is an http.RoundTripper that checks every response it returns.
type Transport struct {
	Next    http.RoundTripper
	Checker *Checker
	Report  func(error)
}

// Transport wraps next; report receives every violation (never ErrNoRoute).
func (c *Checker) Transport(next http.RoundTripper, report func(error)) *Transport {
	return &Transport{Next: next, Checker: c, Report: report}
}

// RoundTrip performs the request and checks the response; the response is
// returned unchanged, its body restored.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.Next.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	var body []byte
	if resp.Body != nil { // a custom transport may return no body
		var rerr error
		body, rerr = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if rerr != nil {
			return nil, rerr
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	t.report(t.Checker.Check(req, resp.StatusCode, resp.Header, body))
	return resp, nil
}

func (t *Transport) report(err error) {
	if err != nil && !errors.Is(err, ErrNoRoute) && t.Report != nil {
		t.Report(err)
	}
}

// Proxy is a reverse proxy to target that checks every response. It rewrites
// the scheme and host of the outgoing URL only: the client's Host header is
// kept, so a server that builds URLs from the request's host sees the proxy's.
// Accept-Encoding is dropped so the buffered body is never compressed. When a
// response body cannot be read, the failure goes to report and the client sees
// the reverse proxy's 502, which the server never sent.
func (c *Checker) Proxy(target *url.URL, report func(error)) http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.Header.Del("Accept-Encoding")
		},
		ModifyResponse: func(resp *http.Response) error {
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				if report != nil {
					report(fmt.Errorf("respcheck: proxy could not read the response to %s %s: %w", resp.Request.Method, resp.Request.URL.Path, err))
				}
				return err
			}
			resp.Body = io.NopCloser(bytes.NewReader(body))
			if e := c.Check(resp.Request, resp.StatusCode, resp.Header, body); e != nil && !errors.Is(e, ErrNoRoute) && report != nil {
				report(e)
			}
			return nil
		},
	}
}
