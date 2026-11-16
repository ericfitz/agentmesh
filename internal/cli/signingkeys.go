package cli

import (
	"context"
	"io"

	"github.com/ericfitz/agentmesh/internal/bus"
)

type opSigningKeyOut struct {
	Thumbprint       string `json:"thumbprint"`
	Serial           string `json:"serial"`
	IssuerThumbprint string `json:"issuer_thumbprint"`
	NotBefore        int64  `json:"not_before"`
	NotAfter         int64  `json:"not_after"`
	State            string `json:"state"`
}

type opSigningKeyListOut struct {
	Keys        []opSigningKeyOut `json:"keys"`
	TrustNumber int64             `json:"trust_number"`
}

type opRevokedLeafOut struct {
	Thumbprint    string `json:"thumbprint"`
	HumanMessages int64  `json:"human_messages"`
}

type opSigningKeyRotationOut struct {
	Current     opSigningKeyOut    `json:"current"`
	Revoked     []opRevokedLeafOut `json:"revoked"`
	TrustNumber int64              `json:"trust_number"`
}

func opSigningKey(k bus.SigningKey) opSigningKeyOut {
	return opSigningKeyOut{Thumbprint: k.Thumbprint, Serial: k.Serial, IssuerThumbprint: k.IssuerThumbprint,
		NotBefore: k.NotBefore, NotAfter: k.NotAfter, State: k.State}
}

// RunSigningKeys implements `agentmesh signing-keys list|rotate`
// (administrator only), the client form of the server's signing leaves; rotate
// always revokes the previous leaf. Where the server has no signing keys (a
// local profile) every action is unavailable (not retryable).
func RunSigningKeys(ctx context.Context, args []string, environ []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return opDispatch(ctx, "signing-keys", map[string]opRunFunc{
		"list":   runSigningKeysList,
		"rotate": runSigningKeysRotate,
	}, args, environ, stdin, stdout, stderr)
}

func runSigningKeysList(ctx context.Context, args []string, environ []string, _ io.Reader, stdout, stderr io.Writer) int {
	c := newOpCmd("signing-keys list", stderr)
	if _, code, ok := c.parse(args, 0, 0); !ok {
		return code
	}
	conn, code := c.connect(ctx, environ)
	if conn == nil {
		return code
	}
	defer func() { _ = conn.Close() }()
	l, err := conn.Bus.ListSigningKeys(ctx)
	if err != nil {
		return fail(stderr, err)
	}
	out := opSigningKeyListOut{Keys: make([]opSigningKeyOut, 0, len(l.Keys)), TrustNumber: l.TrustNumber}
	for _, k := range l.Keys {
		out.Keys = append(out.Keys, opSigningKey(k))
	}
	return opPrint(stdout, stderr, out)
}

func runSigningKeysRotate(ctx context.Context, args []string, environ []string, _ io.Reader, stdout, stderr io.Writer) int {
	c := newOpCmd("signing-keys rotate", stderr)
	idem := c.fs.String("key", "", "idempotency key: a retry with the same key returns the first result")
	if _, code, ok := c.parse(args, 0, 0); !ok {
		return code
	}
	conn, code := c.connect(ctx, environ)
	if conn == nil {
		return code
	}
	defer func() { _ = conn.Close() }()
	res, err := conn.Bus.RotateSigningKey(ctx, bus.RotateSigningKeyInput{IdempotencyKey: *idem})
	if err != nil {
		return fail(stderr, err)
	}
	out := opSigningKeyRotationOut{Current: opSigningKey(res.Current), Revoked: make([]opRevokedLeafOut, 0, len(res.Revoked)), TrustNumber: res.TrustNumber}
	for _, r := range res.Revoked {
		out.Revoked = append(out.Revoked, opRevokedLeafOut{Thumbprint: r.Thumbprint, HumanMessages: r.HumanMessages})
	}
	return opPrint(stdout, stderr, out)
}
