package mcpcli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ericfitz/agentmesh/internal/client"
	"github.com/ericfitz/agentmesh/internal/profile"
)

// maxTokenFile is the largest enrollment token file (open note:
// mcp-only-client 13).
const maxTokenFile = 4096

// commonFlags registers -server, -identity, -credential, -insecure-http,
// -root-thumbprint, -installation and -profile on fs,
// writing into o.
func commonFlags(fs *flag.FlagSet, o *client.Options) {
	fs.StringVar(&o.Server, "server", "", "server URL (default: AGENTMESH_SERVER, then the profile's server)")
	fs.StringVar(&o.Identity, "identity", "", "identity (default: AGENTMESH_IDENTITY, then the profile's identity, then the profile's only credential)")
	fs.StringVar(&o.Credential, "credential", "", "private key file that signs, instead of the credential store (default: AGENTMESH_CREDENTIAL)")
	fs.BoolVar(&o.InsecureHTTP, "insecure-http", false, "accept an http server URL for a host other than 127.0.0.1, ::1 and localhost, for local testing only (default: AGENTMESH_INSECURE_HTTP=1)")
	fs.StringVar(&o.RootThumbprint, "root-thumbprint", "", "pin the trust root: 43 base64url characters, the SHA-256 of the root certificate (default: AGENTMESH_ROOT_THUMBPRINT)")
	fs.StringVar(&o.Installation, "installation", "", "the installation name the server must carry (default: AGENTMESH_INSTALLATION)")
	fs.StringVar(&o.Profile, "profile", "", "profile name (default: AGENTMESH_PROFILE, then .local/agentmesh.json, then default)")
}

// applyEnv fills an empty Server from AGENTMESH_SERVER, an empty Credential
// from AGENTMESH_CREDENTIAL, an empty RootThumbprint from
// AGENTMESH_ROOT_THUMBPRINT, an empty Installation from AGENTMESH_INSTALLATION
// and a false InsecureHTTP from AGENTMESH_INSECURE_HTTP, then makes Credential
// absolute so a later change of the working directory cannot move it. The
// switch's variable accepts 1 (and the empty string, which is unset); any other
// value is an error naming the variable, whatever the flag says.
func applyEnv(o *client.Options, environ []string) error {
	if v, ok := profile.Getenv(environ, "AGENTMESH_INSECURE_HTTP"); ok {
		if v != "1" {
			return fmt.Errorf("AGENTMESH_INSECURE_HTTP must be 1 or empty, got %q", v)
		}
		o.InsecureHTTP = true
	}
	if o.RootThumbprint == "" {
		o.RootThumbprint, _ = profile.Getenv(environ, "AGENTMESH_ROOT_THUMBPRINT")
	}
	if o.Installation == "" {
		o.Installation, _ = profile.Getenv(environ, "AGENTMESH_INSTALLATION")
	}
	if o.Server == "" {
		o.Server, _ = profile.Getenv(environ, "AGENTMESH_SERVER")
	}
	if o.Credential == "" {
		o.Credential, _ = profile.Getenv(environ, "AGENTMESH_CREDENTIAL")
	}
	if o.Credential != "" {
		if abs, err := filepath.Abs(o.Credential); err == nil {
			o.Credential = abs
		}
	}
	return nil
}

// enrollmentToken is the token from, in order, the -enrollment-token flag, the
// -enrollment-token-file file and AGENTMESH_ENROLLMENT_TOKEN; both flags at
// once is an error. The file is trimmed of surrounding white space and must be
// a regular file, non-empty and at most 4 KiB. No error carries the token.
// open note: mcp-only-client 13
func enrollmentToken(flagValue, file string, environ []string) (string, error) {
	if flagValue != "" && file != "" {
		return "", errors.New("-enrollment-token and -enrollment-token-file are exclusive")
	}
	if flagValue != "" {
		return flagValue, nil
	}
	if file != "" {
		return readTokenFile(file)
	}
	v, _ := profile.Getenv(environ, "AGENTMESH_ENROLLMENT_TOKEN")
	return v, nil
}

func readTokenFile(path string) (string, error) {
	// Check before opening: opening a FIFO with no writer blocks forever.
	pre, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("enrollment token file %s: %w", path, errors.Unwrap(err))
	}
	if !pre.Mode().IsRegular() {
		return "", fmt.Errorf("enrollment token file %s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("enrollment token file %s: %w", path, errors.Unwrap(err))
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("enrollment token file %s: %w", path, err)
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("enrollment token file %s is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxTokenFile+1))
	if err != nil {
		return "", fmt.Errorf("enrollment token file %s: %w", path, err)
	}
	if len(b) > maxTokenFile {
		return "", fmt.Errorf("enrollment token file %s is larger than %d bytes", path, maxTokenFile)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("enrollment token file %s is empty", path)
	}
	return tok, nil
}
