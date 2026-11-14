package server

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/ericfitz/agentmesh/internal/auth/assertion"
	"github.com/ericfitz/agentmesh/internal/auth/keys"
	"github.com/ericfitz/agentmesh/internal/auth/token"
	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/identities"
	"github.com/ericfitz/agentmesh/internal/gen"
	"github.com/ericfitz/agentmesh/internal/store"
)

func issuerUnavailable() error {
	return bus.Errorf(bus.CodeUnavailable, false, "token issuer not configured") // not retryable: a configuration state, not an outage
}

// logCause leaves the cause of a bus error (a store outage's driver text,
// which no client sees) in the server log.
func (a *api) logCause(err error) {
	var be *bus.Error
	if errors.As(err, &be) && be.Cause != nil {
		a.log.Warn("token endpoint: request failed", "code", string(be.Code), "cause", be.Cause.Error())
	}
}

// noStoreToken adds the RFC 6749 section 5.1 cache headers to a 200 token
// response.
type noStoreToken struct{ gen.Token200JSONResponse }

func (r noStoreToken) VisitTokenResponse(w http.ResponseWriter) error {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	return r.Token200JSONResponse.VisitTokenResponse(w)
}

// Token is the token endpoint (RFC 6749 section 3.2). Every refusal is an
// oauthError response (spec 8.1), never an error: only this endpoint answers
// the OAuth body. client_credentials is private_key_jwt (Decisions 19, 70,
// 84).
func (a *api) Token(ctx context.Context, req gen.TokenRequestObject) (gen.TokenResponseObject, error) {
	iss := a.opts.Issuer
	if iss == nil {
		return oauthFromBus(issuerUnavailable(), false), nil
	}
	if req.Body == nil {
		return oauthFail(http.StatusBadRequest, "invalid_request", "request body is required"), nil
	}
	if msg, over := checkTokenFormBounds(req.Body); over {
		return oauthFail(http.StatusBadRequest, "invalid_request", "%s", msg), nil
	}
	switch req.Body.GrantType {
	case "":
		return oauthFail(http.StatusBadRequest, "invalid_request", "grant_type is required"), nil
	case "client_credentials":
		return a.clientCredentials(ctx, iss, req.Body), nil
	case grantTokenExchange:
		return a.tokenExchange(ctx, req.Body), nil
	default:
		return oauthFail(http.StatusBadRequest, "unsupported_grant_type", "grant_type %q is not supported", clip(string(req.Body.GrantType))), nil
	}
}

// clientCredentials is the RFC 7523 private_key_jwt grant. Every failure of
// the assertion is invalid_client; scope is ignored and client_id, when
// sent, must be the assertion's issuer.
func (a *api) clientCredentials(ctx context.Context, iss *token.Issuer, b *gen.TokenRequest) gen.TokenResponseObject {
	refuse := func(format string, args ...any) gen.TokenResponseObject {
		return oauthFail(http.StatusUnauthorized, "invalid_client", format, args...)
	}
	if b.ClientAssertionType == nil || *b.ClientAssertionType != assertion.Type {
		return refuse("client_assertion_type must be %s", assertion.Type)
	}
	if b.ClientAssertion == nil || *b.ClientAssertion == "" {
		return refuse("client_assertion is required")
	}
	p, err := assertion.Parse(*b.ClientAssertion)
	if err != nil {
		return refuse("client assertion: %s", err)
	}
	// An empty client_id is omitted (RFC 6749 section 3.2).
	if b.ClientId != nil && *b.ClientId != "" && *b.ClientId != p.Identity {
		return refuse("client_id does not match the assertion issuer")
	}
	pub, _, err := identities.Service{Core: a.core}.PublicKey(ctx, p.Identity, p.KID)
	if err != nil {
		if bus.CodeOf(err) == bus.CodeNotFound {
			return refuse("unknown identity or key")
		}
		a.logCause(err)
		return oauthFromBus(err, false)
	}
	now := a.core.Now()
	if err := p.Verify(pub, []string{iss.URL(), iss.TokenEndpoint()}, now, token.Leeway); err != nil {
		return refuse("%s", err)
	}
	// Verify accepts the assertion until exp plus the leeway inclusive, and
	// the expiry job deletes rows with expires_at < now, so the jti is kept
	// until one second past exp+Leeway: forgetting it at exp would let a
	// replay inside the leeway mint a second bearer. The insert is the whole
	// transaction (Decision 26: no side effects); replicas racing on one
	// (identity, jti) serialize on the primary key and exactly one commits
	// (Decision (Eric, 2026-10-21), Milestone 7 item 4).
	keepUntil := p.Expiry.Add(token.Leeway + time.Second).UnixMilli()
	err = a.core.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		return tx.PutAssertionJTI(ctx, p.Identity, p.JTI, keepUntil)
	})
	if errors.Is(err, store.ErrConflict) {
		return refuse("assertion replayed")
	}
	if err != nil {
		err = core.FromStore(err)
		a.logCause(err)
		return oauthFromBus(err, false)
	}
	raw, exp, err := iss.Mint(ctx, token.MintInput{Identity: p.Identity, Kind: token.KindAgent})
	if errors.Is(err, token.ErrSignerUnavailable) {
		// The client sees the fixed text; the operator finds the cause here.
		a.log.Warn("token grant failed: signing key unavailable", "identity", clip(p.Identity), "error", err.Error())
		return oauthFail(http.StatusServiceUnavailable, "temporarily_unavailable", "the signing key is unavailable")
	}
	if err != nil {
		return oauthFromBus(bus.Internal(err), false)
	}
	return noStoreToken{gen.Token200JSONResponse{
		AccessToken: raw,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn(exp, a.core.Now()),
	}}
}

// Jwks serves the own issuer's public key set.
func (a *api) Jwks(ctx context.Context, _ gen.JwksRequestObject) (gen.JwksResponseObject, error) {
	if a.opts.Issuer == nil {
		return nil, issuerUnavailable()
	}
	set := a.opts.Issuer.JWKS(ctx)
	out := gen.JWKS{Keys: make([]gen.JWK, 0, len(set.Keys))}
	for _, k := range set.Keys {
		b, err := k.MarshalJSON()
		if err != nil {
			return nil, bus.Internal(err)
		}
		var m gen.JWK
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, bus.Internal(err)
		}
		out.Keys = append(out.Keys, m)
	}
	return gen.Jwks200JSONResponse(out), nil
}

// Register binds a public key to an identity under the configured mode
// (Decisions 20, 58, 72). An unset or unrecognized mode refuses every
// register with forbidden and says why; it is never open (Decision 21).
func (a *api) Register(ctx context.Context, req gen.RegisterRequestObject) (gen.RegisterResponseObject, error) {
	if req.Body == nil {
		return nil, core.E(bus.CodeValidation, "request body is required")
	}
	if err := keys.CheckJWKMembers(len(req.Body.PublicKeyJwk)); err != nil {
		return nil, core.E(bus.CodeValidation, "public_key_jwk: %s", err)
	}
	if err := keys.CheckKty(req.Body.PublicKeyJwk["kty"]); err != nil {
		return nil, core.E(bus.CodeValidation, "public_key_jwk: %s", err)
	}
	if err := keys.CheckJWKStrings(req.Body.PublicKeyJwk); err != nil {
		return nil, core.E(bus.CodeValidation, "public_key_jwk: %s", err)
	}
	raw, err := json.Marshal(req.Body.PublicKeyJwk)
	if err != nil {
		return nil, core.E(bus.CodeValidation, "public_key_jwk: %s", err)
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(raw); err != nil {
		return nil, core.E(bus.CodeValidation, "public_key_jwk: %s", err)
	}
	pub, _, _, err := keys.FromJWK(jwk)
	if err != nil {
		return nil, core.E(bus.CodeValidation, "public_key_jwk: %s", err)
	}
	in := identities.RegisterInput{Identity: req.Body.Identity, Key: pub}
	if req.Body.EnrollmentToken != nil {
		in.EnrollmentToken = *req.Body.EnrollmentToken
	}
	res, err := identities.Service{Core: a.core}.Register(ctx, a.opts.Registration, in)
	if err != nil {
		return nil, err
	}
	return gen.Register201JSONResponse{
		Identity:  res.Identity,
		Kid:       res.KID,
		Algorithm: gen.RegistrationAlgorithm(res.Algorithm),
		Created:   res.Created,
	}, nil
}

// expiresIn is the expires_in of a token answer: the whole seconds from now to
// exp, rounded (the issuer's clock reads a few microseconds before the
// handler's, so truncation would answer 3599) and never negative.
func expiresIn(exp, now time.Time) int64 {
	return max(0, int64(math.Round(exp.Sub(now).Seconds())))
}
