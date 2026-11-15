package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/bus/remote"
	"github.com/ericfitz/agentmesh/internal/gen"
	"github.com/ericfitz/agentmesh/internal/profile"
	"github.com/ericfitz/agentmesh/internal/trust"
)

// discoverTimeout bounds the discover call of ensureTrust (spec 4.10).
const discoverTimeout = 10 * time.Second

// ensureTrust is what a process does once when it opens the Bus of a server
// profile (Ruling 24): Store.Check against the profile; unless o.NoDiscover,
// GET /v1/discover within 10 seconds, then Store.Accept and Store.Apply. Every
// refusal is a ResolveError (exit 2), except an unreachable server with no pin,
// which is the error of a call to it. The returned Store is the profile's trust
// directory whether or not it holds a pin; use wrapTrust to put the layer on a
// Bus.
func ensureTrust(ctx context.Context, o Options, r Resolved, plain *gen.ClientWithResponses) (trust.Store, error) {
	p := r.Profile
	st := trust.Store{Dir: trust.Dir(r.ConfigDir, p.Name)}
	exp := trust.Expect{Server: p.Server, RootThumbprint: p.RootThumbprint, Installation: p.Installation}
	say := notifier(o)

	if p.InsecureHTTP && insecureTransport(p.Server) {
		say("profile %s: insecure_http is on; the connection to %s is not protected", p.Name, p.Server)
	}

	_, pinned, err := st.Pinned()
	if err != nil {
		if !o.AcceptNewRoot {
			return st, resolveErr(fmt.Errorf("profile %q: %w", p.Name, err))
		}
		pinned = false // -accept-new-root completes an incomplete pin
	}
	if pinned {
		if err := st.Check(exp); err != nil && !replacesExpected(o, err) {
			return st, resolveErr(fmt.Errorf("profile %q: %w", p.Name, err))
		}
	}
	if o.NoDiscover {
		return st, nil
	}

	dctx, cancel := context.WithTimeout(ctx, discoverTimeout)
	defer cancel()
	res, err := plain.DiscoverWithResponse(dctx)
	if err == nil && res.HTTPResponse.StatusCode != http.StatusOK {
		err = fmt.Errorf("HTTP %d", res.HTTPResponse.StatusCode)
	}
	if err == nil && res.JSON200 == nil {
		err = errors.New("HTTP 200 but the body is not a discovery document")
	}
	if err != nil {
		if pinned {
			say("profile %s: discover at %s failed (%v); going on with the trust held for it", p.Name, p.Server, err)
			return st, nil
		}
		return st, fmt.Errorf("discover %s: %w", p.Server, err)
	}
	if res.JSON200.Trust == nil {
		return st, resolveErr(fmt.Errorf("the server at %s sent no trust material", p.Server))
	}
	b := toTrustBundle(remote.FromGenTrustBundle(*res.JSON200.Trust))
	acc, err := st.Accept(b, exp, o.AcceptNewRoot)
	if err != nil {
		var me *trust.MismatchError
		if errors.As(err, &me) {
			return st, resolveErr(fmt.Errorf("profile %q: %w", p.Name, err))
		}
		return st, resolveErr(fmt.Errorf("profile %q: trust directory %s: %w", p.Name, st.Dir, err))
	}
	switch {
	case acc.Replaced:
		say("profile %s: replaced pinned root %s, installation %s, with root %s, installation %s (%s)",
			p.Name, acc.Old.Thumbprint, acc.Old.Installation, acc.New.Thumbprint, acc.New.Installation, p.Server)
	case acc.First:
		say("pinned root %s, installation %s, for profile %s (%s)", acc.New.Thumbprint, acc.New.Installation, p.Name, p.Server)
	}
	rep, err := st.Apply(b)
	if err != nil {
		return st, resolveErr(fmt.Errorf("profile %q: trust directory %s: %w", p.Name, st.Dir, err))
	}
	reportRefused(o, r, rep)
	return st, nil
}

// replacesExpected is true when -accept-new-root lets a Check failure about the
// profile's expected root or installation go on to Accept, which checks the
// expectation against the new root itself.
func replacesExpected(o Options, err error) bool {
	var me *trust.MismatchError
	return o.AcceptNewRoot && errors.As(err, &me) && strings.HasPrefix(me.What, "expected ")
}

// insecureTransport is an http URL to a host that is not loopback.
func insecureTransport(server string) bool {
	u, err := url.Parse(server)
	return err == nil && u.Scheme == "http" && !profile.LoopbackHost(u.Hostname())
}

func notifier(o Options) func(format string, a ...any) {
	return func(format string, a ...any) {
		if o.Notice != nil {
			o.Notice(fmt.Sprintf(format, a...))
		}
	}
}

// toTrustBundle converts a Bus bundle to the store's; the one place.
func toTrustBundle(b bus.TrustBundle) trust.Bundle {
	return trust.Bundle{
		TrustNumber:   b.TrustNumber,
		Intermediates: b.Intermediates,
		RootCRL:       b.RootCRL,
		LeafCRLs:      b.LeafCRLs,
		Root:          b.Root,
		Installation:  b.Installation,
	}
}

// reportRefused says each refused CRL once on the notice and once in
// <data dir>/logs/trust.log, with both numbers.
func reportRefused(o Options, r Resolved, rep trust.Report) {
	for _, c := range rep.Refused {
		which := "root"
		if c.IssuerKey != "" {
			which = "leaf (issuer key " + c.IssuerKey + ")"
		}
		line := fmt.Sprintf("profile %s: the server's %s CRL number %d is below the held number %d; it was refused", r.Profile.Name, which, c.Got, c.Held)
		notifier(o)("%s", line)
		appendTrustLog(r.DataDir, line)
	}
}

// appendTrustLog is best effort: a log that cannot be written never fails a call.
func appendTrustLog(dataDir, line string) {
	if dataDir == "" {
		return
	}
	dir := filepath.Join(dataDir, "logs")
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "trust.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339), line)
	_ = f.Close()
}

// wrapTrust puts the trust layer on b when the profile holds a pin. With no
// pin (NoDiscover on a first run) the layer sends no number and applies
// nothing, so b is returned as it is.
func wrapTrust(b bus.Bus, st trust.Store, o Options, r Resolved) bus.Bus {
	if _, ok, err := st.Pinned(); err != nil || !ok {
		return b
	}
	return &trustBus{Bus: b, store: st, o: o, r: r}
}

// trustBus is the layer under the Bus (spec 2 adds verification here). It
// embeds the remote Bus and replaces three methods: each sends the trust
// number the store holds, and open and receive store the bundle they get.
type trustBus struct {
	bus.Bus
	store trust.Store
	o     Options
	r     Resolved
}

// number is the held trust number, or nil before any bundle was applied.
func (b *trustBus) number() (*int64, error) {
	n, ok, err := b.store.TrustNumber()
	if err != nil {
		return nil, fmt.Errorf("profile %q: trust directory %s: %w", b.r.Profile.Name, b.store.Dir, err)
	}
	if !ok {
		return nil, nil
	}
	return &n, nil
}

// apply stores a returned bundle. A failure is a notice and a log line, not an
// error: the call's own answer (a session, a delivered batch) must reach the
// caller, and the next call brings the bundle again because the number held
// still differs.
func (b *trustBus) apply(tb *bus.TrustBundle) {
	if tb == nil {
		return
	}
	rep, err := b.store.Apply(toTrustBundle(*tb))
	if err != nil {
		line := fmt.Sprintf("profile %s: storing the trust bundle in %s failed: %v", b.r.Profile.Name, b.store.Dir, err)
		notifier(b.o)("%s", line)
		appendTrustLog(b.r.DataDir, line)
		return
	}
	reportRefused(b.o, b.r, rep)
}

func (b *trustBus) Open(ctx context.Context, in bus.OpenSessionInput) (bus.Session, error) {
	n, err := b.number()
	if err != nil {
		return bus.Session{}, err
	}
	in.TrustNumber = n
	s, err := b.Bus.Open(ctx, in)
	if err != nil {
		return s, err
	}
	b.apply(s.Trust)
	return s, nil
}

func (b *trustBus) Receive(ctx context.Context, in bus.ReceiveInput) (bus.ReceiveResult, error) {
	n, err := b.number()
	if err != nil {
		return bus.ReceiveResult{}, err
	}
	in.TrustNumber = n
	r, err := b.Bus.Receive(ctx, in)
	if err != nil {
		return r, err
	}
	b.apply(r.Trust)
	return r, nil
}

// Watch sends the held number; a wake for a number that differs carries no
// bundle (count 0), and the next Open or Receive stores it.
func (b *trustBus) Watch(ctx context.Context, in bus.WatchInput) (bus.WatchResult, error) {
	n, err := b.number()
	if err != nil {
		return bus.WatchResult{}, err
	}
	in.TrustNumber = n
	return b.Bus.Watch(ctx, in)
}
