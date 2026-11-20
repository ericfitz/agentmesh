package profile

import (
	"strings"
	"testing"
)

func TestRedactURL(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://user:pw@h.example", "https://h.example"},
		{"https://token@h.example/p", "https://h.example/p"},
		{"https://u:p/w@h.example", "https://h.example"},
		{"https://h.example/?token=s3cret", "https://h.example/?..."},
		{"https://h.example/#frag-secret", "https://h.example/#..."},
		{"http://u:pw@h:bad", "http://h:bad"},
		{"u:pw@h", "(an unparseable value with user info)"},
		{"https://h.example", "https://h.example"},
	} {
		if got := RedactURL(tc.in); got != tc.want {
			t.Errorf("RedactURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// No validation error of a URL setting echoes the user info, the query or the
// fragment (issue #44).
func TestURLErrorsNeverEchoSecrets(t *testing.T) {
	const secret = "s3cretpw"
	for _, s := range []string{
		"https://user:" + secret + "@h.example",
		"ftp://user:" + secret + "@h.example",
		"https://" + secret + "@h.example",
		"https://h.example/?token=" + secret,
		"https://h.example/#" + secret,
		"http://user:" + secret + "@h:bad",
		"https://user:" + secret + "@h.example/path",
	} {
		errs := []error{
			OIDC{Issuer: s, ClientID: "c"}.Validate(),
			validServer(Profile{Mode: ModeServer, Server: s}),
		}
		for i, err := range errs {
			if err == nil {
				t.Errorf("%q (%d): accepted", s, i)
			} else if strings.Contains(err.Error(), secret) {
				t.Errorf("%q (%d): the error echoes the secret: %v", s, i, err)
			}
		}
	}
}
