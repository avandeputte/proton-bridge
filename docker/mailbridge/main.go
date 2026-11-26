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
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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
	DataDir    string
	BridgeBin  string
	LogLevel   string
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

	bridge := NewBridge(cfg)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		bridge.Run(ctx)
	}()

	for _, addr := range cfg.IMAPListen {
		startForwarder(ctx, &wg, "IMAP", addr, bridge.IMAPTarget)
	}
	for _, addr := range cfg.SMTPListen {
		startForwarder(ctx, &wg, "SMTP", addr, bridge.SMTPTarget)
	}

	if err := serveWeb(ctx, cfg, auth, bridge); err != nil {
		log.Printf("web server stopped: %v", err)
		stop()
	}

	wg.Wait()
	log.Print("shut down cleanly")
}
