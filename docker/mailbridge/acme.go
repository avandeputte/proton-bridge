package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
)

// acmeStamp is the date and time lego starts its log lines with.
var acmeStamp = regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d `)

// Pauses after failed attempts. Let's Encrypt allows only a handful of failed
// validations per hour, so these start long and grow.
var acmeRetry = []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 6 * time.Hour}

// ACMEStatus is shown in the web UI.
type ACMEStatus struct {
	// State is one of: waiting (no certificate yet), ok, error.
	State   string    `json:"state"`
	Message string    `json:"message,omitempty"`
	Domains []string  `json:"domains"`
	Next    time.Time `json:"next"`
}

// ACME gets a certificate from Let's Encrypt, or another ACME certificate
// authority, and keeps it renewed. The work is done by lego with the DNS
// challenge, which is the one that works for a server that cannot be reached
// from the internet; this type decides when to run it and hands the result to
// the CertStore.
type ACME struct {
	cfg   Config
	certs *CertStore
	dir   string

	mu     sync.Mutex
	status ACMEStatus
}

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

func NewACME(cfg Config, certs *CertStore) *ACME {
	// One directory per certificate authority: a test certificate from the
	// staging server must not be taken for the real one after switching.
	ca := "ca"
	if u, err := url.Parse(cfg.ACMEServer); err == nil && u.Host != "" {
		ca = strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
				return r
			}
			return '_'
		}, strings.ToLower(u.Host))
	}
	return &ACME{
		cfg:    cfg,
		certs:  certs,
		dir:    filepath.Join(cfg.DataDir, "acme", ca),
		status: ACMEStatus{State: "waiting", Message: "Starting.", Domains: cfg.ACMEDomains},
	}
}

func (a *ACME) Status() ACMEStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status
}

func (a *ACME) setStatus(state, message string, next time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status.State, a.status.Message, a.status.Next = state, message, next
}

// files are where lego keeps the certificate (with its chain) and the key.
func (a *ACME) files() (certPath, keyPath string) {
	name := strings.ReplaceAll(a.cfg.ACMEDomains[0], "*", "_")
	base := filepath.Join(a.dir, "certificates", name)
	return base + ".crt", base + ".key"
}

func (a *ACME) have() bool {
	certPath, keyPath := a.files()
	for _, path := range []string{certPath, keyPath} {
		if fi, err := os.Stat(path); err != nil || fi.Size() == 0 {
			return false
		}
	}
	return true
}

// use hands lego's current certificate to everything that presents one.
func (a *ACME) use() error {
	certPath, keyPath := a.files()
	return a.certs.Load(certPath, keyPath, certLetsEncrypt)
}

// UseStored puts the certificate of an earlier run to use, so that it is
// there from the first connection on.
func (a *ACME) UseStored() {
	if !a.have() {
		return
	}
	if err := a.use(); err != nil {
		log.Printf("certificate: the stored certificate cannot be used: %v", err)
	}
}

// lego runs one lego command and returns the informative end of its output on failure.
func (a *ACME) lego(ctx context.Context, command ...string) error {
	args := []string{"--accept-tos", "--path", a.dir, "--server", a.cfg.ACMEServer, "--dns", a.cfg.ACMEDNS}
	for _, d := range a.cfg.ACMEDomains {
		args = append(args, "--domains", d)
	}
	if a.cfg.ACMEEmail != "" {
		args = append(args, "--email", a.cfg.ACMEEmail)
	}
	for _, r := range a.cfg.ACMEResolvers {
		args = append(args, "--dns.resolvers", r)
	}
	args = append(args, a.cfg.ACMEArgs...)
	args = append(args, command...)

	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, a.cfg.ACMEBin, args...) // #nosec G204 -- configuration, not user input
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 10 * time.Second
	// lego reads the DNS provider's credentials from its environment. The
	// web UI password is none of its business.
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "MAILBRIDGE_PASSWORD") {
			cmd.Env = append(cmd.Env, kv)
		}
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

// Run gets the certificate and keeps it renewed until ctx is cancelled.
func (a *ACME) Run(ctx context.Context) {
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		log.Printf("certificate: %v", err)
		a.setStatus("error", err.Error(), time.Time{})
		return
	}

	failures := 0
	for {
		var err error
		if a.have() {
			err = a.lego(ctx, "renew", "--dynamic", "--no-random-sleep", "--force-cert-domains")
		} else {
			log.Printf("certificate: requesting one for %s", strings.Join(a.cfg.ACMEDomains, ", "))
			a.setStatus("waiting", "Requesting a certificate for "+strings.Join(a.cfg.ACMEDomains, ", ")+". This usually takes a minute or two.", time.Time{})
			err = a.lego(ctx, "run")
		}
		if ctx.Err() != nil {
			return
		}
		if err == nil && a.have() {
			err = a.use()
		}

		// Not on the dot, so that everyone's checks do not arrive together.
		wait := acmeCheckInterval + rand.N(time.Hour) //nolint:gosec
		switch {
		case err != nil:
			wait = acmeRetry[min(failures, len(acmeRetry)-1)]
			failures++
			log.Printf("certificate: attempt failed, trying again in %s", wait)
			a.setStatus("error", err.Error(), time.Now().Add(wait))
		default:
			failures = 0
			a.setStatus("ok", "", time.Now().Add(wait))
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
