package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	acmeProduction = "https://acme-v02.api.letsencrypt.org/directory"
	acmeStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// How often to ask whether the certificate is due for renewal. lego
	// decides: when a third of the lifetime is left, or when the CA says so.
	acmeCheckInterval = 12 * time.Hour
	acmeErrLines      = 8

	acmeMaxDomains   = 20
	acmeMaxVariables = 40
	acmeMaxValue     = 8192
)

// acmeStamp is the date and time lego starts its log lines with.
var acmeStamp = regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d `)

// Pauses after failed attempts. Let's Encrypt allows only a handful of failed
// validations per hour, so these start long and grow.
var acmeRetry = []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 6 * time.Hour}

// DNS providers that run a program of the user's choosing or want someone at a
// terminal. Those are for the environment, not for a web form.
var acmeNotInWebUI = map[string]bool{"exec": true, "manual": true}

var (
	acmeProviderCode = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	acmeHelpVariable = regexp.MustCompile(`^\s+- "([A-Z][A-Z0-9_]*)":\s*(.*)$`)
)

// ACMESettings say which certificate to get and how to prove that the domain
// is ours. They come from the environment, or else from the web UI, which
// keeps them in the data directory.
type ACMESettings struct {
	Domains []string `json:"domains"`
	DNS     string   `json:"dns"` // lego's code for the DNS provider
	Email   string   `json:"email"`
	// Staging asks Let's Encrypt's test server, which hands out certificates
	// nobody trusts but is generous with attempts.
	Staging   bool     `json:"staging"`
	Resolvers []string `json:"resolvers"`
	// Variables are the DNS provider's credentials and options, which lego
	// reads from its environment.
	Variables map[string]string `json:"variables"`
}

func (s ACMESettings) enabled() bool { return len(s.Domains) > 0 }

// ACMEStatus is shown in the web UI.
type ACMEStatus struct {
	// State is one of: waiting (no certificate yet), ok, error.
	State   string    `json:"state"`
	Message string    `json:"message,omitempty"`
	Domains []string  `json:"domains"`
	Staging bool      `json:"staging"`
	Next    time.Time `json:"next"`
}

// ProviderVariable is one setting of a DNS provider.
type ProviderVariable struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ProviderInfo is what lego documents about a DNS provider.
type ProviderInfo struct {
	Code        string             `json:"code"`
	Name        string             `json:"name"`
	Credentials []ProviderVariable `json:"credentials"`
	Options     []ProviderVariable `json:"options"`
	URL         string             `json:"url"`
}

// allows says whether name is one of the provider's variables. Most also
// exist with _FILE appended, naming a file to read the value from.
func (p ProviderInfo) allows(name string) bool {
	name = strings.TrimSuffix(name, "_FILE")
	for _, list := range [][]ProviderVariable{p.Credentials, p.Options} {
		for _, v := range list {
			if v.Name == name {
				return true
			}
		}
	}
	return false
}

// ACME gets a certificate from Let's Encrypt, or another ACME certificate
// authority, and keeps it renewed. The work is done by lego with the DNS
// challenge, which is the one that works for a server that cannot be reached
// from the internet; this type decides when to run it and hands the result to
// the CertStore.
type ACME struct {
	cfg   Config
	certs *CertStore
	path  string // where settings from the web UI are kept
	// locked says why the web UI cannot change the settings: "environment"
	// when they are set there, "certificate" when the user brought their own.
	locked string

	mu         sync.Mutex
	settings   ACMESettings
	generation int // counts changes of the settings
	status     ACMEStatus
	abort      context.CancelFunc // stops the lego run in progress
	wake       chan struct{}

	helpMu    sync.Mutex
	providers []string
	help      map[string]ProviderInfo
}

func NewACME(cfg Config, certs *CertStore) *ACME {
	a := &ACME{
		cfg:   cfg,
		certs: certs,
		path:  filepath.Join(cfg.DataDir, "acme.json"),
		wake:  make(chan struct{}, 1),
		help:  map[string]ProviderInfo{},
	}
	switch {
	case len(cfg.ACMEDomains) > 0:
		a.locked = "environment"
		a.settings = ACMESettings{Domains: cfg.ACMEDomains, DNS: cfg.ACMEDNS}
	case cfg.TLSCert != "":
		a.locked = "certificate"
	default:
		data, err := os.ReadFile(a.path)
		if err == nil {
			err = json.Unmarshal(data, &a.settings)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("certificate: cannot read the Let's Encrypt settings in %s, carrying on without: %v", a.path, err)
			a.settings = ACMESettings{}
		}
	}
	a.status = a.freshStatus(a.settings)
	return a
}

func (a *ACME) freshStatus(s ACMESettings) ACMEStatus {
	return ACMEStatus{State: "waiting", Message: "Starting.", Domains: s.Domains, Staging: a.server(s) == acmeStaging}
}

// Locked says why the settings cannot be changed in the web UI, if so.
func (a *ACME) Locked() string { return a.locked }

// Settings are the settings in use.
func (a *ACME) Settings() ACMESettings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.settings
}

// Status describes the state of the certificate request. There is none
// while no Let's Encrypt certificate is asked for.
func (a *ACME) Status() (ACMEStatus, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status, a.settings.enabled()
}

// setStatus records how the attempt for the settings of the given generation
// went. A report about settings that were replaced meanwhile is dropped.
func (a *ACME) setStatus(generation int, state, message string, next time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if generation == a.generation {
		a.status.State, a.status.Message, a.status.Next = state, message, next
	}
}

func (a *ACME) poke() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

// Retry makes the next attempt happen now instead of after the pause.
func (a *ACME) Retry() { a.poke() }

// validDomain accepts host names and wildcards such as *.example.com.
func validDomain(d string) bool {
	d = strings.TrimPrefix(d, "*.")
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	labels := strings.Split(d, ".")
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return false // an IP address, or nothing a certificate authority knows
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// Configure takes new settings from the web UI, stores them and starts
// working on them. Settings without domains turn Let's Encrypt off.
//
// A variable in keep is carried over from the current settings: the web UI
// never gets to see the values, so it cannot send them back.
func (a *ACME) Configure(ctx context.Context, s ACMESettings, keep []string) error {
	switch a.locked {
	case "environment":
		return errors.New("the Let's Encrypt settings are made with environment variables, change them there")
	case "certificate":
		return errors.New("the container was given a certificate with MAILBRIDGE_TLS_CERT, remove that to use Let's Encrypt")
	}

	clean := ACMESettings{Staging: s.Staging, Variables: map[string]string{}}
	if len(s.Domains) > 0 {
		seen := map[string]bool{}
		for _, d := range s.Domains {
			d = strings.ToLower(strings.TrimSpace(d))
			switch {
			case d == "" || seen[d]:
				continue
			case !validDomain(d):
				return fmt.Errorf("%q is not a domain name", d)
			}
			seen[d] = true
			clean.Domains = append(clean.Domains, d)
		}
		if len(clean.Domains) == 0 || len(clean.Domains) > acmeMaxDomains {
			return fmt.Errorf("enter between 1 and %d domain names", acmeMaxDomains)
		}

		clean.DNS = strings.ToLower(strings.TrimSpace(s.DNS))
		if !acmeProviderCode.MatchString(clean.DNS) {
			return errors.New("choose the DNS provider of the domain")
		}
		if acmeNotInWebUI[clean.DNS] {
			return fmt.Errorf("the DNS provider %q can only be set up with environment variables", clean.DNS)
		}
		provider, err := a.Provider(ctx, clean.DNS)
		if err != nil {
			return err
		}

		if clean.Email = strings.TrimSpace(s.Email); clean.Email != "" {
			if addr, err := mail.ParseAddress(clean.Email); err != nil || addr.Address != clean.Email {
				return errors.New("the contact address is not an email address")
			}
		}
		for _, r := range s.Resolvers {
			if r = strings.TrimSpace(r); r == "" {
				continue
			}
			if _, _, err := net.SplitHostPort(r); err != nil {
				if strings.ContainsAny(r, " \t/") || strings.HasPrefix(r, "-") {
					return fmt.Errorf("%q is not a DNS resolver, enter something like 1.1.1.1:53", r)
				}
				r = net.JoinHostPort(r, "53")
			}
			clean.Resolvers = append(clean.Resolvers, r)
		}

		current := a.Settings()
		for _, name := range keep {
			if value, ok := current.Variables[name]; ok && current.DNS == clean.DNS {
				clean.Variables[name] = value
			}
		}
		for name, value := range s.Variables {
			if value != "" {
				clean.Variables[name] = value
			}
		}
		if len(clean.Variables) > acmeMaxVariables {
			return errors.New("too many settings for the DNS provider")
		}
		for name, value := range clean.Variables {
			// Only what lego documents for this provider: the names end up
			// in the environment of a program.
			if !provider.allows(name) {
				return fmt.Errorf("%s is not a setting of the DNS provider %s", name, clean.DNS)
			}
			if len(value) > acmeMaxValue || strings.ContainsAny(value, "\x00\r\n") {
				return fmt.Errorf("the value of %s is not usable", name)
			}
		}
	}

	data, err := json.MarshalIndent(clean, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(a.path+".tmp", data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(a.path+".tmp", a.path); err != nil {
		return err
	}

	a.mu.Lock()
	a.settings = clean
	a.generation++
	a.status = a.freshStatus(clean)
	if a.abort != nil {
		a.abort()
	}
	a.mu.Unlock()

	if !clean.enabled() {
		log.Print("certificate: Let's Encrypt was turned off in the web UI")
		if err := a.certs.Fallback(); err != nil {
			log.Printf("certificate: cannot go back to the self-signed certificate: %v", err)
		}
	}
	a.poke()
	return nil
}

// --- what lego knows about DNS providers -----------------------------------------

// dnshelp returns lego's description of DNS providers.
func (a *ACME) dnshelp(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	// --path only keeps lego from making a directory where it happens to run.
	args = append([]string{"--path", filepath.Join(a.cfg.DataDir, "acme"), "dnshelp"}, args...)
	out, err := exec.CommandContext(ctx, a.cfg.ACMEBin, args...).CombinedOutput() // #nosec G204 -- the code is validated
	if err != nil {
		return "", fmt.Errorf("cannot ask lego about DNS providers: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Providers lists the codes of the DNS providers the web UI offers.
func (a *ACME) Providers(ctx context.Context) ([]string, error) {
	a.helpMu.Lock()
	defer a.helpMu.Unlock()
	if a.providers != nil {
		return a.providers, nil
	}
	out, err := a.dnshelp(ctx)
	if err != nil {
		return nil, err
	}
	_, list, ok := strings.Cut(out, "Supported DNS providers:")
	if !ok {
		return nil, errors.New("cannot ask lego about DNS providers: unexpected answer")
	}
	list, _, _ = strings.Cut(strings.TrimSpace(list), "\n")
	var providers []string
	for _, code := range strings.Split(list, ",") {
		if code = strings.TrimSpace(code); acmeProviderCode.MatchString(code) && !acmeNotInWebUI[code] {
			providers = append(providers, code)
		}
	}
	if len(providers) == 0 {
		return nil, errors.New("cannot ask lego about DNS providers: unexpected answer")
	}
	a.providers = providers
	return providers, nil
}

// Provider describes one DNS provider: above all, the names of its credentials.
func (a *ACME) Provider(ctx context.Context, code string) (ProviderInfo, error) {
	if !acmeProviderCode.MatchString(code) || acmeNotInWebUI[code] {
		return ProviderInfo{}, fmt.Errorf("%q is not a DNS provider that can be set up here", code)
	}
	a.helpMu.Lock()
	defer a.helpMu.Unlock()
	if info, ok := a.help[code]; ok {
		return info, nil
	}
	out, err := a.dnshelp(ctx, "-c", code)
	if err != nil {
		if strings.Contains(err.Error(), "not yet supported") {
			return ProviderInfo{}, fmt.Errorf("%q is not a DNS provider lego knows", code)
		}
		return ProviderInfo{}, err
	}
	info := parseProviderHelp(code, out)
	a.help[code] = info
	return info, nil
}

func parseProviderHelp(code, out string) ProviderInfo {
	info := ProviderInfo{Code: code, Name: code, Credentials: []ProviderVariable{}, Options: []ProviderVariable{}}
	var section *[]ProviderVariable
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Configuration for ") && info.Name == code:
			info.Name = strings.TrimSuffix(strings.TrimPrefix(trimmed, "Configuration for "), ".")
		case trimmed == "Credentials:":
			section = &info.Credentials
		case trimmed == "Additional Configuration:":
			section = &info.Options
		case strings.HasPrefix(trimmed, "More information: "):
			info.URL = strings.TrimPrefix(trimmed, "More information: ")
		case section != nil:
			if m := acmeHelpVariable.FindStringSubmatch(line); m != nil {
				*section = append(*section, ProviderVariable{Name: m[1], Description: m[2]})
			}
		}
	}
	return info
}

// --- running lego ----------------------------------------------------------------

// server is the certificate authority's directory for the given settings.
func (a *ACME) server(s ACMESettings) string {
	if s.Staging {
		return acmeStaging
	}
	return a.cfg.ACMEServer
}

// dir is where lego keeps the account and certificates. One directory per
// certificate authority: a test certificate from the staging server must not
// be taken for the real one after switching.
func (a *ACME) dir(s ACMESettings) string {
	ca := "ca"
	if u, err := url.Parse(a.server(s)); err == nil && u.Host != "" {
		ca = strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
				return r
			}
			return '_'
		}, strings.ToLower(u.Host))
	}
	return filepath.Join(a.cfg.DataDir, "acme", ca)
}

// files are where lego keeps the certificate (with its chain) and the key.
func (a *ACME) files(s ACMESettings) (certPath, keyPath string) {
	name := strings.ReplaceAll(s.Domains[0], "*", "_")
	base := filepath.Join(a.dir(s), "certificates", name)
	return base + ".crt", base + ".key"
}

func (a *ACME) have(s ACMESettings) bool {
	certPath, keyPath := a.files(s)
	for _, path := range []string{certPath, keyPath} {
		if fi, err := os.Stat(path); err != nil || fi.Size() == 0 {
			return false
		}
	}
	return true
}

// use hands lego's current certificate to everything that presents one.
func (a *ACME) use(s ACMESettings) error {
	certPath, keyPath := a.files(s)
	return a.certs.Load(certPath, keyPath, certLetsEncrypt)
}

// UseStored puts the certificate of an earlier run to use, so that it is
// there from the first connection on.
func (a *ACME) UseStored() {
	s := a.Settings()
	if !s.enabled() || !a.have(s) {
		return
	}
	if err := a.use(s); err != nil {
		log.Printf("certificate: the stored certificate cannot be used: %v", err)
	}
}

// lego runs one lego command and returns the informative end of its output on failure.
func (a *ACME) lego(ctx context.Context, s ACMESettings, command ...string) error {
	args := []string{"--accept-tos", "--path", a.dir(s), "--server", a.server(s), "--dns", s.DNS}
	for _, d := range s.Domains {
		args = append(args, "--domains", d)
	}
	email := s.Email
	if email == "" {
		email = a.cfg.ACMEEmail
	}
	if email != "" {
		args = append(args, "--email", email)
	}
	resolvers := s.Resolvers
	if len(resolvers) == 0 {
		resolvers = a.cfg.ACMEResolvers
	}
	for _, r := range resolvers {
		args = append(args, "--dns.resolvers", r)
	}
	args = append(args, a.cfg.ACMEArgs...)
	args = append(args, command...)

	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, a.cfg.ACMEBin, args...) // #nosec G204 -- validated settings, never a shell
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 10 * time.Second
	// lego reads the DNS provider's credentials from its environment. The
	// web UI password is none of its business.
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "MAILBRIDGE_PASSWORD") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	names := make([]string, 0, len(s.Variables))
	for name := range s.Variables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		cmd.Env = append(cmd.Env, name+"="+s.Variables[name])
	}

	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	var tail []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(pr)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Fprintln(os.Stdout, "[lego] "+line)
			// For the web UI: what went wrong, without the progress reports.
			if line = strings.TrimSpace(acmeStamp.ReplaceAllString(line, "")); line != "" && !strings.HasPrefix(line, "[INFO]") {
				if tail = append(tail, line); len(tail) > acmeErrLines {
					tail = tail[1:]
				}
			}
		}
		_, _ = io.Copy(io.Discard, pr)
	}()

	err := cmd.Run()
	_ = pw.Close()
	<-done

	if err == nil {
		return nil
	}
	if ctx.Err() != nil && len(tail) == 0 {
		return ctx.Err()
	}
	if len(tail) == 0 {
		return fmt.Errorf("lego failed: %v", err)
	}
	return fmt.Errorf("%s", strings.Join(tail, "\n"))
}

// attempt gets or renews the certificate once.
func (a *ACME) attempt(ctx context.Context, s ACMESettings, generation int) error {
	if err := os.MkdirAll(a.dir(s), 0o700); err != nil {
		return err
	}
	if a.have(s) {
		// Back to settings that were in use before: their certificate is
		// good right away.
		if err := a.use(s); err != nil {
			log.Printf("certificate: the stored certificate cannot be used: %v", err)
		}
		if err := a.lego(ctx, s, "renew", "--dynamic", "--no-random-sleep", "--force-cert-domains"); err != nil {
			return err
		}
	} else {
		domains := strings.Join(s.Domains, ", ")
		log.Printf("certificate: requesting one for %s", domains)
		a.setStatus(generation, "waiting", "Requesting a certificate for "+domains+". This usually takes a minute or two.", time.Time{})
		if err := a.lego(ctx, s, "run"); err != nil {
			return err
		}
	}
	if !a.have(s) {
		return errors.New("lego finished without leaving a certificate")
	}
	return a.use(s)
}

// Run gets the certificate and keeps it renewed until ctx is cancelled. It
// follows the settings as they change.
func (a *ACME) Run(ctx context.Context) {
	failures, lastGeneration := 0, -1
	for {
		a.mu.Lock()
		s, generation := a.settings, a.generation
		runCtx, abort := context.WithCancel(ctx)
		a.abort = abort
		a.mu.Unlock()
		if generation != lastGeneration {
			failures, lastGeneration = 0, generation
		}

		var wait time.Duration
		if s.enabled() {
			err := a.attempt(runCtx, s, generation)
			if ctx.Err() != nil {
				abort()
				return
			}
			if runCtx.Err() != nil {
				abort()
				continue // the settings changed under way
			}
			if err != nil {
				wait = acmeRetry[min(failures, len(acmeRetry)-1)]
				failures++
				log.Printf("certificate: attempt failed, trying again in %s", wait)
				a.setStatus(generation, "error", err.Error(), time.Now().Add(wait))
			} else {
				failures = 0
				// Not on the dot, so that everyone's checks do not arrive together.
				wait = acmeCheckInterval + rand.N(time.Hour) //nolint:gosec
				a.setStatus(generation, "ok", "", time.Now().Add(wait))
			}
		}
		abort()

		var timer <-chan time.Time
		if s.enabled() {
			timer = time.After(wait)
		}
		select {
		case <-ctx.Done():
			return
		case <-timer:
		case <-a.wake:
		}
	}
}
