package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/bus/remote"
	"github.com/ericfitz/agentmesh/internal/gen"
	"github.com/ericfitz/agentmesh/internal/profile"
	"github.com/ericfitz/agentmesh/internal/trust"
)

// ServerInfo is what GET /v1/discover says about a server.
type ServerInfo struct{ ServerVersion, ProtocolVersion string }

// DiscoverServer is GET /v1/discover with no bearer: the liveness probe. A
// non-200 answer, an undecodable body and a body with no protocol version (not
// an agentmesh server) are errors that name what came back. hc nil: a client
// with no Timeout. It exists so internal/mcpcli never imports internal/gen.
func DiscoverServer(ctx context.Context, hc *http.Client, server string) (ServerInfo, error) {
	gc, err := unauthenticated(hc, server)
	if err != nil {
		return ServerInfo{}, err
	}
	r, err := gc.DiscoverWithResponse(ctx)
	if err != nil {
		return ServerInfo{}, fmt.Errorf("discover %s: %w", server, err)
	}
	if r.HTTPResponse.StatusCode != http.StatusOK {
		return ServerInfo{}, fmt.Errorf("discover %s: HTTP %d", server, r.HTTPResponse.StatusCode)
	}
	if r.JSON200 == nil {
		return ServerInfo{}, fmt.Errorf("discover %s: HTTP 200 but the body is not a discovery document", server)
	}
	if r.JSON200.ProtocolVersion == "" {
		return ServerInfo{}, fmt.Errorf("discover %s: the answer names no protocol version, so it is not an agentmesh server", server)
	}
	return ServerInfo{ServerVersion: r.JSON200.ServerVersion, ProtocolVersion: r.JSON200.ProtocolVersion}, nil
}

// EnsureServerTrust is the trust step of Open for the server profile that
// SelectProfile chooses for o (an undefined profile with o.Server is the
// in-memory one): it pins the root on first contact and applies the bundle, or
// refuses with a *ResolveError (exit 2) naming both roots when the root,
// installation or server differs from the pinned one and o.AcceptNewRoot is
// false. `agentmesh-mcponly check` runs it as part of its reach step. hc nil: a
// client with no Timeout.
func EnsureServerTrust(ctx context.Context, o Options, hc *http.Client) error {
	sel, err := SelectProfile(o)
	if err != nil {
		return err
	}
	p := sel.Profile
	if !sel.Defined {
		if o.Server == "" {
			return resolveErr(fmt.Errorf("profile %q is not defined in %s", sel.Name, sel.Config.Path))
		}
		p = profile.Profile{Name: sel.Name, Mode: profile.ModeServer, Server: strings.TrimSuffix(o.Server, "/"), InsecureHTTP: o.InsecureHTTP, RootThumbprint: o.RootThumbprint, Installation: o.Installation}
	}
	if p.Mode != profile.ModeServer {
		return NoLocalModeError(p.Name)
	}
	plain, err := unauthenticated(hc, p.Server)
	if err != nil {
		return err
	}
	dataDir, err := profile.DataDir(o.Environ)
	if err != nil {
		return resolveErr(err)
	}
	_, err = ensureTrust(ctx, o, Resolved{Profile: p, ConfigDir: sel.ConfigDir, DataDir: dataDir}, plain)
	return err
}

// IsRootMismatch reports whether err is the refusal of a changed root,
// installation name or server URL, which -accept-new-root replaces.
func IsRootMismatch(err error) bool {
	var me *trust.MismatchError
	return errors.As(err, &me) && (me.What == "root" || me.What == "installation" || me.What == "server")
}

// ProbeHealth is the health document at the probe tier: GET /v1/health with no
// bearer, through the remote Bus.
func ProbeHealth(ctx context.Context, hc *http.Client, server string) (bus.Health, error) {
	gc, err := unauthenticated(hc, server)
	if err != nil {
		return bus.Health{}, err
	}
	return remote.New(gc).Health(ctx)
}

func unauthenticated(hc *http.Client, server string) (*gen.ClientWithResponses, error) {
	if hc == nil {
		hc = &http.Client{}
	}
	gc, err := gen.NewClientWithResponses(strings.TrimSuffix(server, "/"), gen.WithHTTPClient(hc))
	if err != nil {
		return nil, resolveErr(fmt.Errorf("server %q: %w", server, err))
	}
	return gc, nil
}
