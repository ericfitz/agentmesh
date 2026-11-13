package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"github.com/ericfitz/agentmesh/internal/server/config"
)

type cfgT = config.Config

func rsaKey() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) }

func newEd25519() (ed25519.PublicKey, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	return pub, err
}
