package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/ericfitz/agentmesh/internal/auth/token"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/embed"
	"github.com/ericfitz/agentmesh/internal/core/identities"
	"github.com/ericfitz/agentmesh/internal/core/inspect"
	"github.com/ericfitz/agentmesh/internal/core/notify"
	"github.com/ericfitz/agentmesh/internal/core/notify/pgnotify"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/server"
	"github.com/ericfitz/agentmesh/internal/server/config"
	"github.com/ericfitz/agentmesh/internal/slackapi"
	"github.com/ericfitz/agentmesh/internal/slackapi/slackgo"
	"github.com/ericfitz/agentmesh/internal/slackbridge"
)

// Run is `agentmesh server` (Decision 85): the configuration comes from the
// -config file, the AGENTMESH_SERVER_* variables in environ and the flags,
// and `server admin ...` dispatches to RunAdmin. Exit codes: 0 clean shutdown
// or -h, 1 runtime error, 2 flag or configuration error. Ported from v1
// main.go (run's subcommand dispatch, flag.ContinueOnError, parseExit).
func Run(ctx context.Context, args []string, environ []string, stdout, stderr io.Writer) int {
	return run(ctx, args, environ, stdout, stderr, Serve)
}

// RunWith is Run with the serving function injected. The e2e fixture of
// internal/e2e uses it to put the Slack fake (internal/slackapi/slackfake)
// in Config.Slack before Serve runs; the binary's main calls Run. It is
// reachable from Go code of this module only: no flag, setting, variable or
// build tag selects another serving function.
func RunWith(ctx context.Context, args []string, environ []string, stdout, stderr io.Writer, serve func(context.Context, Config) error) int {
	return run(ctx, args, environ, stdout, stderr, serve)
}

// run is Run with the serving function injected, so a test can look at the
// Config the flags produce without serving.
//
// State (Definition of Done D, ADR 0019 section 5, "Server start"): the trust
// settings, the root and the intermediate key are checked before the Store is
// opened, so a start that fails there leaves nothing. signingkeys.New then
// issues this process's leaf and stores its row: a second start issues another
// leaf (the first still verifies until it expires or is revoked), replicas
// start independently and each issues its own, a start that fails before the
// row is stored leaves nothing and one that fails after it leaves an unused
// leaf row. Exit 2 is a configuration or trust state an operator must change,
// exit 1 a Store or key service failure the next start retries.
func run(ctx context.Context, args []string, environ []string, stdout, stderr io.Writer, serve func(context.Context, Config) error) int {
	if len(args) > 0 && args[0] == "admin" {
		return RunAdmin(ctx, args[1:], environ, stdout, stderr)
	}
	var f flags
	fs := flagSet("agentmesh server", &f, true)
	var usage bytes.Buffer
	fs.SetOutput(&usage)
	if code, done := parseFlags(fs, args, &usage, stdout, stderr); done {
		return code
	}
	fail := func(code int, format string, a ...any) int {
		_, _ = fmt.Fprintf(stderr, "agentmesh server: "+format+"\n", a...)
		return code
	}
	if fs.NArg() > 0 {
		return fail(2, "unexpected argument %q", fs.Arg(0))
	}
	cfg, cc, err := loadConfig(&f, fs, environ)
	if err != nil {
		return fail(2, "%v", err)
	}
	if cfg.Listen == "" {
		return fail(2, "listen is required, for example 127.0.0.1:0 (set listen)")
	}
	local, err := ClassifyListen(cfg.Listen)
	if err != nil {
		return fail(2, "%v", err)
	}
	// An unknown registration value never reaches Serve: ParseMode rejects it
	// here as well as in config.Validate (the register handler's refusal of an
	// unset or unrecognized mode is only a backstop).
	var mode identities.Mode
	switch {
	case cfg.Registration != "":
		if mode, err = identities.ParseMode(cfg.Registration); err != nil {
			return fail(2, "registration: %v", err)
		}
	case local:
		mode = identities.ModeOpen
	default:
		mode = identities.ModeEnrollment
	}
	// The socket path is not a host, so a unix listener has no default issuer.
	if cfg.Issuer == "" && strings.HasPrefix(cfg.Listen, "unix:") {
		return fail(2, "issuer is required when listen is a unix socket (set issuer)")
	}

	logger := newLogger(cfg, stderr)
	for _, w := range cfg.Warnings() {
		logger.Warn(w)
	}

	// The Slack tokens are read before the store is opened, so a bad file
	// changes nothing.
	slackClient, err := slackClientFor(cfg, logger)
	if err != nil {
		return fail(2, "%v", err)
	}

	// The root and the intermediate key are checked before the store is opened.
	root, provider, err := openStartTrust(ctx, cfg, time.Now())
	if err != nil {
		return fail(startExit(err), "%v", err)
	}

	st, err := openStore(ctx, cfg, logger)
	if err != nil {
		return fail(1, "%v", err)
	}
	defer func() { _ = st.Close() }()

	// Bind before building the issuer: the default issuer URL is the bound address.
	ln, err := Listen(cfg.Listen)
	if err != nil {
		return fail(1, "listen: %v", err)
	}
	defer func() { _ = ln.Close() }() // Serve closes it too; a second Close is harmless

	issuerURL := cfg.Issuer
	if issuerURL == "" {
		issuerURL = "http://" + boundAuthority(cfg.Listen, ln.Addr())
		if !local {
			_, _ = fmt.Fprintf(stdout, "issuer is unset: clients will see %s in openid-configuration (set issuer)\n", issuerURL)
		}
	}

	// This Core exists only for the trust rules; Serve builds the serving one.
	c, err := core.New(st, cc, core.Options{Now: time.Now, Logger: logger})
	if err != nil {
		return fail(1, "%v", err)
	}
	manager, err := signingkeys.New(ctx, signingkeys.Options{
		Trust:        signingkeys.Trust{Core: c, Root: root, Installation: cfg.InstallationName, Provider: provider},
		LeafValidity: cfg.LeafValidity(),
	})
	if err != nil {
		return fail(startExit(startFailure(cfg, err)), "signing key: %v", err)
	}
	issuer, err := token.NewIssuer(ctx, issuerURL, manager, time.Duration(cfg.TokenLifetimeSeconds)*time.Second, c.Now)
	if err != nil {
		return fail(1, "issuer: %v", err)
	}
	// A rotation, a renewal or a reload that changes the leaves reloads this
	// process's issuer at once.
	manager.SetOnChange(issuer.Invalidate)

	ext := externalIssuers(cfg)

	var embedder core.Embedder
	if cfg.EmbeddingEndpoint != "" {
		key, err := apiKey("embedding_api_key_file", cfg.EmbeddingAPIKeyFile, "embedding_api_key_env", cfg.EmbeddingAPIKeyEnv, environ)
		if err != nil {
			return fail(2, "%v", err)
		}
		embedder = embed.NewHTTP(cfg.EmbeddingEndpoint, cfg.EmbeddingModel, key, nil)
	}

	var inspector core.Inspector
	if cfg.InspectionEndpoint != "" {
		key, err := apiKey("inspection_api_key_file", cfg.InspectionAPIKeyFile, "inspection_api_key_env", cfg.InspectionAPIKeyEnv, environ)
		if err != nil {
			return fail(2, "%v", err)
		}
		inspector = inspect.NewWebhook(cfg.InspectionEndpoint, key, nil)
	}

	notifier, closeNotifier := storeNotifier(ctx, cfg, logger)
	defer closeNotifier()

	engine := "postgres"
	if cfg.SQLite != "" {
		engine = "sqlite"
	}
	err = serve(ctx, Config{
		Listen:       cfg.Listen,
		Listener:     ln,
		Store:        st,
		Notifier:     notifier,
		Auth:         server.Bearer{Verifier: token.Verifier{Own: issuer}},
		Cfg:          &cc,
		Logger:       logger,
		Registration: mode,
		Issuer:       issuer,
		SigningKeys:  manager,
		External:     ext,
		Embedder:     embedder,
		Inspector:    inspector,
		Slack:        slackClient,
		SlackCfg: slackbridge.Config{
			ArchiveAfterDone: time.Duration(cfg.SlackArchiveAfterDoneHours) * time.Hour,
			MaxMessageChars:  cfg.SlackMaxMessageChars,
			CanvasEnabled:    cfg.SlackCanvasEnabled,
			CanvasCoalesce:   time.Duration(cfg.SlackCanvasCoalesceSeconds) * time.Second,
			Logger:           logger,
		},
		Ready: func(a net.Addr) {
			thumb, notAfter := manager.Current()
			_, _ = fmt.Fprintf(stdout, "agentmesh server listening on %s (%s, registration %s, issuer %s, leaf %s until %s)\n",
				a, engine, mode, issuer.URL(), thumb, notAfter.UTC().Format(time.RFC3339))
		},
	})
	if err != nil {
		return fail(1, "%v", err)
	}
	return 0
}

// storeNotifier is the Notifier Serve gets for cfg's store, and the function
// that ends it. A Postgres store shares hints across replicas through
// LISTEN/NOTIFY (Decision 52), so it gets a pgnotify listener that lives as
// long as Run; SQLite gets nil, Serve's in-process Memory (Milestone 4 choice
// 14: two servers over one SQLite file do not share hints).
func storeNotifier(ctx context.Context, cfg config.Config, logger *slog.Logger) (notify.Notifier, func()) {
	if cfg.Postgres == "" {
		return nil, func() {}
	}
	l := pgnotify.New(ctx, cfg.Postgres, pgnotify.Options{Logger: logger})
	return l, l.Close
}

// boundAuthority is the bound address as a URL authority. A wildcard listen
// address binds dual-stack, and the kernel then reports "[::]:port" even for
// "0.0.0.0:port"; the configured literal host is kept in that case, so the
// URL (and the warning about it) names what the operator typed.
func boundAuthority(listen string, bound net.Addr) string {
	host, port, err := net.SplitHostPort(bound.String())
	if err != nil {
		return bound.String()
	}
	if cfgHost, _, err := net.SplitHostPort(listen); err == nil && cfgHost != "" {
		if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
			host = cfgHost
		}
	}
	return net.JoinHostPort(host, port)
}

// logLevel maps the validated log_level setting.
func logLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// externalIssuers maps cfg.Issuers onto token.External. An unset claim name or
// human lifetime stays empty: token.External applies the defaults (spec 5.1).
// Validate has already limited
// algorithms to EdDSA, ES256 and RS256; an empty list keeps the verifier's
// default of all three.
func externalIssuers(cfg config.Config) []*token.External {
	var out []*token.External
	for _, i := range cfg.Issuers {
		var algs []jose.SignatureAlgorithm
		for _, a := range i.Algorithms {
			algs = append(algs, jose.SignatureAlgorithm(a))
		}
		out = append(out, &token.External{
			Name: i.Name, Issuer: i.Issuer, JWKSURI: i.JWKSURI, Audience: i.Audience,
			Algorithms: algs,
			Claims: token.ClaimNames{
				Email:         i.Claims.Email,
				EmailVerified: i.Claims.EmailVerified,
				Groups:        i.Claims.Groups,
				Subject:       i.Claims.Subject,
			},
			TrustUnverifiedEmail: i.TrustUnverifiedEmail,
			HumanLifetime:        time.Duration(i.HumanTokenLifetimeSeconds) * time.Second,
			TTL:                  time.Duration(cfg.JWKSRefreshSeconds) * time.Second,
		})
	}
	return out
}

// apiKey reads an API key from the file the setting fileSetting names (file)
// or from the variable the setting envSetting names (env) in environ; neither
// set means no key. Validate allows at most one of the two. An error names the
// setting, never the key.
func apiKey(fileSetting, file, envSetting, env string, environ []string) (string, error) {
	switch {
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("%s: %w", fileSetting, err)
		}
		return nonEmptyKey(fileSetting, strings.TrimSpace(string(b)))
	case env != "":
		prefix := env + "="
		val := ""
		for _, kv := range environ {
			if v, ok := strings.CutPrefix(kv, prefix); ok {
				val = v
			}
		}
		if val == "" {
			return "", fmt.Errorf("%s names %s, which is not set", envSetting, env)
		}
		return nonEmptyKey(envSetting, strings.TrimSpace(val))
	}
	return "", nil
}

// nonEmptyKey refuses a key that is blank after trimming: a named key setting
// that yields no key would send requests with no credential.
func nonEmptyKey(setting, key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("%s: the key is empty", setting)
	}
	return key, nil
}

// slackClientFor reads the two Slack token files and builds the adapter; nil
// when no Slack setting is present (the bridge is off). Validate has already
// required both files or neither. An error names the setting, never a token or
// any file content.
func slackClientFor(cfg config.Config, logger *slog.Logger) (slackapi.Client, error) {
	if cfg.SlackAppTokenFile == "" {
		return nil, nil
	}
	read := func(setting, path string) (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			var pe *os.PathError
			if errors.As(err, &pe) {
				err = pe.Err // the path is the operator's own; the reason is enough
			}
			return "", fmt.Errorf("%s: %w", setting, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	app, err := read("slack_app_token_file", cfg.SlackAppTokenFile)
	if err != nil {
		return nil, err
	}
	bot, err := read("slack_bot_token_file", cfg.SlackBotTokenFile)
	if err != nil {
		return nil, err
	}
	return slackgo.New(app, bot, slackgo.Options{Logger: logger, HTTP: &http.Client{Timeout: slackHTTPTimeout}})
}

// slackHTTPTimeout bounds every Slack Web API call, so a Slack that accepts
// connections and never answers cannot block the start-up auth.test.
const slackHTTPTimeout = 30 * time.Second
