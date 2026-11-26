// Command mailbridge runs Proton Mail Bridge headless inside a container.
//
// It supervises the bridge process, drives it through the same gRPC API the
// official desktop GUI uses, serves a password-protected web UI for
// configuration, and forwards LAN-facing IMAP/SMTP ports to the bridge, which
// only ever listens on 127.0.0.1.
package main

import (
	"context"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Config is read once from the environment at start-up.
type Config struct {
	WebListen  string
	TLSMode    string // "on" or "off"
	TLSCert    string
	TLSKey     string
	Password   string // optional fixed web UI password
	IMAPListen []string
	SMTPListen []string
	IMAPPort   string // port shown to the user (the one published on the host)
	SMTPPort   string
	Hostname   string // host name shown to the user, empty = whatever the browser used
	// PublicURL is where browsers find the web UI when it is not reached
	// directly: the address of the reverse proxy in front of it.
	PublicURL *url.URL
	DataDir   string
	BridgeBin string
	LogLevel  string

	// Dovecot mode: mail clients talk to a bundled Dovecot, which is kept in
	// two-way sync with bridge.
	DovecotMode      bool
	IMAPSListen      []string
	IMAPSPort        string
	MailDir          string
	SyncFastInterval time.Duration
	SyncFastBoxes    []string
	SyncFullInterval time.Duration
	SyncMaxDelete    int
	SyncExclude      []string
	SyncDebug        bool

	// A Let's Encrypt (ACME) certificate, fetched and renewed by lego.
	ACMEDomains   []string
	ACMEDNS       string // lego's code for the DNS provider
	ACMEEmail     string
	ACMEServer    string // directory URL of the certificate authority
	ACMEResolvers []string
	ACMEArgs      []string // further options for lego
	ACMEBin       string
}

func envBool(key string, def bool) bool {
	switch strings.ToLower(env(key, "")) {
	case "":
		return def
	case "on", "true", "1", "yes":
		return true
	case "off", "false", "0", "no":
		return false
	}
	log.Fatalf("%s must be \"on\" or \"off\"", key)
	return def
}

func envDuration(key string, def, floor time.Duration) time.Duration {
	v := env(key, "")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < floor {
		log.Fatalf("%s must be a duration of at least %s, such as \"30s\" or \"5m\"", key, floor)
	}
	return d
}

func envInt(key string, def int) int {
	v := env(key, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		log.Fatalf("%s must be a non-negative number", key)
	}
	return n
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" && p != "off" {
			out = append(out, p)
		}
	}
	return out
}

func portOf(addrs []string, def string) string {
	if len(addrs) == 0 {
		return def
	}
	if i := strings.LastIndex(addrs[0], ":"); i >= 0 {
		return addrs[0][i+1:]
	}
	return def
}

func loadConfig() Config {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("cannot determine home directory: %v", err)
	}

	c := Config{
		WebListen:  env("MAILBRIDGE_WEB_LISTEN", ":8080"),
		TLSMode:    strings.ToLower(env("MAILBRIDGE_TLS", "on")),
		TLSCert:    env("MAILBRIDGE_TLS_CERT", ""),
		TLSKey:     env("MAILBRIDGE_TLS_KEY", ""),
		Password:   os.Getenv("MAILBRIDGE_PASSWORD"),
		IMAPListen: splitList(env("MAILBRIDGE_IMAP_LISTEN", ":143")),
		SMTPListen: splitList(env("MAILBRIDGE_SMTP_LISTEN", ":587")),
		Hostname:   env("MAILBRIDGE_HOSTNAME", ""),
		DataDir:    env("MAILBRIDGE_DATA", filepath.Join(home, "mailbridge")),
		BridgeBin:  env("BRIDGE_BIN", "/usr/lib/protonmail/bridge/bridge"),
		LogLevel:   env("BRIDGE_LOG_LEVEL", "info"),
	}
	c.DovecotMode = envBool("MAILBRIDGE_DOVECOT", false)
	c.IMAPSListen = splitList(env("MAILBRIDGE_IMAPS_LISTEN", ""))
	c.MailDir = env("MAILBRIDGE_MAIL_DIR", filepath.Join(home, "dovecot"))
	c.SyncFastInterval = envDuration("MAILBRIDGE_SYNC_INTERVAL", 15*time.Second, 5*time.Second)
	c.SyncFastBoxes = splitList(env("MAILBRIDGE_SYNC_FOLDERS", "INBOX,Sent"))
	c.SyncFullInterval = envDuration("MAILBRIDGE_SYNC_FULL_INTERVAL", 5*time.Minute, 30*time.Second)
	c.SyncMaxDelete = envInt("MAILBRIDGE_SYNC_MAX_DELETE", 100)
	c.SyncExclude = splitList(env("MAILBRIDGE_SYNC_EXCLUDE", "All Mail,Starred"))
	c.SyncDebug = envBool("MAILBRIDGE_SYNC_DEBUG", false)
	if len(c.IMAPSListen) > 0 {
		c.IMAPSPort = env("MAILBRIDGE_IMAPS_PORT", portOf(c.IMAPSListen, "993"))
	}
	c.ACMEDomains = splitList(strings.ToLower(env("MAILBRIDGE_ACME_DOMAINS", "")))
	c.ACMEDNS = env("MAILBRIDGE_ACME_DNS", "")
	c.ACMEEmail = env("MAILBRIDGE_ACME_EMAIL", "")
	c.ACMEServer = env("MAILBRIDGE_ACME_SERVER", acmeProduction)
	c.ACMEResolvers = splitList(env("MAILBRIDGE_ACME_RESOLVERS", ""))
	c.ACMEArgs = strings.Fields(env("MAILBRIDGE_ACME_LEGO_ARGS", ""))
	c.ACMEBin = env("LEGO_BIN", "lego")
	switch strings.ToLower(c.ACMEServer) {
	case "production":
		c.ACMEServer = acmeProduction
	case "staging":
		c.ACMEServer = acmeStaging
	}
	switch {
	case (len(c.ACMEDomains) > 0) != (c.ACMEDNS != ""):
		log.Fatal("a Let's Encrypt certificate needs both MAILBRIDGE_ACME_DOMAINS and MAILBRIDGE_ACME_DNS")
	case len(c.ACMEDomains) > 0 && (c.TLSCert != "" || c.TLSKey != ""):
		log.Fatal("set either MAILBRIDGE_ACME_DOMAINS or MAILBRIDGE_TLS_CERT and MAILBRIDGE_TLS_KEY, not both")
	case (c.TLSCert != "") != (c.TLSKey != ""):
		log.Fatal("MAILBRIDGE_TLS_CERT and MAILBRIDGE_TLS_KEY must be set together")
	}
	for _, d := range c.ACMEDomains {
		if !validDomain(d) {
			log.Fatalf("MAILBRIDGE_ACME_DOMAINS: %q is not a domain name", d)
		}
	}
	if raw := env("MAILBRIDGE_PUBLIC_URL", ""); raw != "" {
		u, err := parsePublicURL(raw)
		if err != nil {
			log.Fatalf("MAILBRIDGE_PUBLIC_URL: %v", err)
		}
		c.PublicURL = u
	}
	c.IMAPPort = env("MAILBRIDGE_IMAP_PORT", portOf(c.IMAPListen, "143"))
	c.SMTPPort = env("MAILBRIDGE_SMTP_PORT", portOf(c.SMTPListen, "587"))

	if file := env("MAILBRIDGE_PASSWORD_FILE", ""); file != "" {
		data, err := os.ReadFile(file) //nolint:gosec
		if err != nil {
			log.Fatalf("cannot read MAILBRIDGE_PASSWORD_FILE: %v", err)
		}
		c.Password = strings.TrimRight(string(data), "\r\n")
	}

	switch c.TLSMode {
	case "on", "off":
	case "true", "1", "yes":
		c.TLSMode = "on"
	case "false", "0", "no":
		c.TLSMode = "off"
	default:
		log.Fatalf("MAILBRIDGE_TLS must be \"on\" or \"off\", got %q", c.TLSMode)
	}

	return c
}

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("[mailbridge] ")

	cfg := loadConfig()

	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := healthcheck(cfg); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatalf("cannot create data directory %s: %v", cfg.DataDir, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	auth, err := NewAuth(cfg)
	if err != nil {
		log.Fatalf("cannot initialise web UI authentication: %v", err)
	}

	certs, err := NewCertStore(cfg)
	if err != nil {
		log.Fatalf("cannot set up the TLS certificate: %v", err)
	}

	bridge := NewBridge(cfg)

	var wg sync.WaitGroup
	run := func(fn func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(ctx)
		}()
	}

	run(bridge.Run)

	acme := NewACME(cfg, certs)
	acme.UseStored()
	run(acme.Run)
	if cfg.TLSCert != "" {
		// certbot, acme.sh and the like renew the files in place.
		run(func(ctx context.Context) { certs.Watch(ctx, cfg.TLSCert, cfg.TLSKey, certOwn) })
	}

	// Bridge always presents its own self-signed certificate. While there is
	// a certificate that mail clients trust, mailbridge answers them itself.
	// Every mail port takes clients that ask for STARTTLS and clients that
	// start TLS right away, so that neither setting in a mail client is wrong.
	ports := NewPorts(ctx, &wg, cfg)
	trouble := &mailTrouble{certs: certs, notify: bridge.notify}
	smtp := &mailProxy{name: "SMTP", proto: "smtp", certs: certs, upstream: bridge.SMTPEndpoint, pinned: bridge.TLSCertificate,
		active: certs.Trusted, trouble: trouble.certificate}
	ports.Handle(svcSMTP, smtp.handle)

	var syncer *SyncManager
	if cfg.DovecotMode {
		// Mail clients talk to Dovecot; mailbridge keeps Dovecot and bridge in sync.
		dovecot := NewDovecot(cfg, certs)
		dovecot.onLog = trouble.dovecotLine
		if err := dovecot.Prepare(); err != nil {
			log.Fatalf("cannot set up Dovecot mode: %v", err)
		}
		certs.OnChange(func() { dovecot.Reload(ctx) })
		syncer = NewSyncManager(cfg, dovecot, bridge)

		run(dovecot.Run)
		run(syncer.Run)

		toDovecot := func(name string) handler {
			return func(ctx context.Context, conn net.Conn) {
				conn, startsTLS := startsWithTLS(conn)
				target := dovecotIMAPAddr
				if startsTLS {
					target = dovecotIMAPSAddr
				}
				forward(ctx, name, conn, target, true)
			}
		}
		ports.Handle(svcIMAP, toDovecot("IMAP"))
		ports.Handle(svcIMAPS, toDovecot("IMAPS"))
	} else {
		if len(cfg.IMAPSListen) > 0 {
			log.Fatal("MAILBRIDGE_IMAPS_LISTEN needs MAILBRIDGE_DOVECOT=on; without Dovecot, the IMAP port takes SSL/TLS as well as STARTTLS")
		}
		imap := &mailProxy{name: "IMAP", proto: "imap", certs: certs, pinned: bridge.TLSCertificate, active: certs.Trusted, trouble: trouble.certificate,
			upstream: func() (string, bool) {
				host, port, ssl := bridge.IMAPEndpoint()
				return net.JoinHostPort(host, strconv.Itoa(port)), ssl
			}}
		ports.Handle(svcIMAP, imap.handle)
	}
	for _, problem := range ports.Start() {
		bridge.notify("error", "%s", problem)
	}

	if err := serveWeb(ctx, &server{cfg: cfg, auth: auth, bridge: bridge, syncer: syncer, certs: certs, acme: acme, ports: ports, public: NewPublic(cfg)}); err != nil {
		log.Printf("web server stopped: %v", err)
		stop()
	}

	wg.Wait()
	log.Print("shut down cleanly")
}
