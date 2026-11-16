package config

import (
	"strings"
	"testing"
	"time"
)

func TestTrustSettingsDefaults(t *testing.T) {
	d := Default()
	if d.LeafValidityHours != 168 || d.LeafValidity() != 168*time.Hour {
		t.Errorf("leaf_validity_hours = %d (%v), want 168", d.LeafValidityHours, d.LeafValidity())
	}
	if d.RootCertificateFile != "" || d.IntermediateKeyFile != "" || d.IntermediateKeyURI != "" || d.InstallationName != "" {
		t.Errorf("trust strings not empty: %+v", d)
	}
	if err := valid().Validate(); err != nil {
		t.Errorf("defaults rejected: %v", err)
	}
}

func TestTrustSettingsValidation(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
		want string // "" accepted
	}{
		{"hours 1", func(c *Config) { c.LeafValidityHours = 1 }, "leaf_validity_hours"},
		{"hours 721", func(c *Config) { c.LeafValidityHours = 721 }, "leaf_validity_hours"},
		{"hours 2", func(c *Config) { c.LeafValidityHours = 2 }, ""},
		{"hours 720", func(c *Config) { c.LeafValidityHours = 720 }, ""},
		{"name upper", func(c *Config) { c.InstallationName = "Prod" }, "installation_name"},
		{"name long", func(c *Config) { c.InstallationName = strings.Repeat("a", 65) }, "installation_name"},
		{"name ok", func(c *Config) { c.InstallationName = "prod" }, ""},
		{"uri ftp", func(c *Config) { c.IntermediateKeyURI = "ftp://x" }, "intermediate_key_uri"},
		{"uri ok", func(c *Config) { c.IntermediateKeyURI = "awskms://alias/mesh" }, ""},
		{"both keys", func(c *Config) {
			c.IntermediateKeyURI = "awskms://alias/mesh"
			c.IntermediateKeyFile = "/k.pem"
		}, "intermediate_key_file"},
	}
	for _, tc := range cases {
		c := valid()
		tc.mut(&c)
		err := c.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: rejected: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err %v, want it to name %q", tc.name, err, tc.want)
		}
	}
	c := valid()
	c.IntermediateKeyURI = "ftp://user:hunter2@host/key?token=s3cret"
	err := c.Validate()
	if err == nil {
		t.Fatal("bad scheme accepted")
	}
	for _, leak := range []string{"hunter2", "s3cret", "user:"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q leaks %q", err, leak)
		}
	}
	c = valid()
	c.IntermediateKeyURI = "awskms://user:hunter2@host/key"
	c.IntermediateKeyFile = "/k.pem"
	if err := c.Validate(); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("both-keys error %v", err)
	}
}

func TestLifetimeWithinHalfTheLeaf(t *testing.T) {
	c := valid()
	c.LeafValidityHours = 2
	c.TokenLifetimeSeconds = 3600
	if err := c.Validate(); err != nil {
		t.Errorf("3600 with W 2 rejected: %v", err)
	}
	c.TokenLifetimeSeconds = 3601
	err := c.Validate()
	if err == nil || err.Error() != "token_lifetime_seconds 3601 is more than half of leaf_validity_hours 2 (3600 seconds)" {
		t.Errorf("3601 with W 2: %v", err)
	}
	c = valid()
	c.LeafValidityHours = 2
	c.Issuers = []Issuer{goodIssuer()} // human lifetime 0 means 900
	if err := c.Validate(); err != nil {
		t.Errorf("default human lifetime with W 2 rejected: %v", err)
	}
	c.Issuers[0].HumanTokenLifetimeSeconds = 3600
	if err := c.Validate(); err != nil {
		t.Errorf("human 3600 with W 2 rejected: %v", err)
	}
	c.Issuers[0].HumanTokenLifetimeSeconds = 3601
	err = c.Validate()
	if err == nil || !strings.Contains(err.Error(), "human_token_lifetime_seconds 3601 is more than half of leaf_validity_hours 2 (3600 seconds)") {
		t.Errorf("human 3601 with W 2: %v", err)
	}
}

func TestRequireTrust(t *testing.T) {
	full := func() Config {
		c := valid()
		c.RootCertificateFile = "/root.pem"
		c.InstallationName = "prod"
		c.IntermediateKeyFile = "/k.pem"
		return c
	}
	if err := full().RequireTrust(); err != nil {
		t.Errorf("complete set: %v", err)
	}
	c := full()
	c.IntermediateKeyFile, c.IntermediateKeyURI = "", "awskms://alias/mesh"
	if err := c.RequireTrust(); err != nil {
		t.Errorf("uri variant: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"no root", func(c *Config) { c.RootCertificateFile = "" }, "root_certificate_file"},
		{"no name", func(c *Config) { c.InstallationName = "" }, "installation_name"},
		{"no key", func(c *Config) { c.IntermediateKeyFile = "" }, "intermediate_key_file"},
		{"both keys", func(c *Config) { c.IntermediateKeyURI = "awskms://alias/mesh" }, "intermediate_key_uri"},
	}
	for _, tc := range cases {
		c := full()
		tc.mut(&c)
		if err := c.RequireTrust(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want it to name %q", tc.name, err, tc.want)
		}
	}
}
