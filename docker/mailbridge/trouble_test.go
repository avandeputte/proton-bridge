package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestStartsWithTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	type result struct {
		tls   bool
		first string
	}
	results := make(chan result)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn, startsTLS := startsWithTLS(conn)
			// Whatever was looked at must still be there to read.
			buf := make([]byte, 5)
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.WriteString(conn, "* OK\r\n")
			n, _ := io.ReadFull(conn, buf)
			results <- result{startsTLS, string(buf[:n])}
			_ = conn.Close()
		}
	}()

	// A client that starts TLS by itself.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = tls.Client(conn, &tls.Config{InsecureSkipVerify: true}).Handshake() }() //nolint:gosec
	if got := <-results; !got.tls || got.first[0] != 0x16 {
		t.Fatalf("a TLS client was taken for %+v", got)
	}
	_ = conn.Close()

	// A client that waits for the greeting, as IMAP and SMTP clients do.
	conn, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	greeting := make([]byte, 6)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(conn, "a NOOP\r\n")
	if got := <-results; got.tls || got.first != "a NOO" {
		t.Fatalf("a client that waited was taken for %+v", got)
	}
}

func TestMailTrouble(t *testing.T) {
	selfSigned, err := NewCertStore(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := testCert(t, "mail.example")
	trusted, err := NewCertStore(Config{DataDir: t.TempDir(), TLSCert: certPath, TLSKey: keyPath})
	if err != nil {
		t.Fatal(err)
	}

	var notices []string
	notify := func(_, format string, args ...any) { notices = append(notices, fmt.Sprintf(format, args...)) }
	const session = "user=<>, rip=192.168.1.20, lip=172.21.0.2, session=<hBUz8DNhWIXAqAFX>"

	// What a proxy's health check, a port scan and ordinary sessions leave
	// in Dovecot's log is nobody's trouble.
	quiet := &mailTrouble{certs: selfSigned, notify: notify}
	for _, line := range []string{
		"Nov 26 20:39:21 imap-login: Info: Disconnected: Connection closed (no auth attempts in 0 secs): " + session,
		"Nov 26 20:43:22 imap-login: Info: Disconnected: Connection closed (disconnected before auth was ready, waited 0 secs): " + session,
		"Nov 26 20:40:00 imap-login: Info: Login: user=<jane@example.com>, method=PLAIN, rip=192.168.1.20, lip=172.21.0.2, mpid=77, TLS, session=<x>",
		"Nov 26 19:41:45 indexer-worker(jane@example.com)<2379><x>: Info: FTS Xapian: Done indexing 'INBOX' (auth failed, alert unknown ca)",
		"Nov 26 20:35:04 master: Warning: SIGHUP received - reloading configuration",
	} {
		quiet.dovecotLine(line)
	}
	if len(notices) != 0 {
		t.Fatalf("notices for nothing: %q", notices)
	}

	quiet.dovecotLine("Nov 26 20:40:00 imap-login: Info: Disconnected: Connection closed (auth failed, 1 attempts in 2 secs): user=<jane@example.com>, method=PLAIN, rip=192.168.1.20, lip=172.21.0.2, TLS, session=<x>")
	if len(notices) != 1 || !strings.Contains(notices[0], "192.168.1.20") || !strings.Contains(notices[0], "jane@example.com") || !strings.Contains(notices[0], "bridge password") {
		t.Fatalf("a wrong password: %q", notices)
	}

	notices = nil
	rejected := "Nov 26 20:40:00 imap-login: Info: Disconnected: Connection closed: SSL_accept() failed: error:0A000418:SSL routines::tlsv1 alert unknown ca: SSL alert number 48 (no auth attempts in 0 secs): user=<>, rip=2001:db8::20, lip=2001:db8::1, TLS handshaking: SSL_accept() failed: error:0A000418:SSL routines::tlsv1 alert unknown ca: SSL alert number 48, session=<x>"
	quiet.dovecotLine(rejected)
	if len(notices) != 1 || !strings.Contains(notices[0], "2001:db8::20") || !strings.Contains(notices[0], "self-signed") || !strings.Contains(notices[0], "Let's Encrypt") {
		t.Fatalf("a self-signed certificate turned down: %q", notices)
	}

	notices = nil
	(&mailTrouble{certs: trusted, notify: notify}).dovecotLine(rejected)
	if len(notices) != 1 || strings.Contains(notices[0], "self-signed") || !strings.Contains(notices[0], "mail.example") {
		t.Fatalf("a trusted certificate turned down: %q", notices)
	}

	for msg, want := range map[string]bool{
		"TLS with the mail client: remote error: tls: unknown certificate authority":         true,
		"TLS with the mail client: remote error: tls: bad certificate":                       true,
		"TLS with the mail client: remote error: tls: unknown certificate":                   true,
		"TLS with the mail client: remote error: tls: expired certificate":                   true,
		"TLS with the mail client: read tcp 172.21.0.2:587->192.168.1.87:49560: i/o timeout": false,
		"TLS with the mail client: EOF":                                                      false,
		"TLS with bridge: remote error: tls: internal error":                                 false,
	} {
		if _, got := certTurnedDown(msg); got != want {
			t.Errorf("certTurnedDown(%q) = %v", msg, got)
		}
	}
}

// A client that does not trust the certificate is reported with its address.
func TestMailProxyReportsRejectedCertificate(t *testing.T) {
	reported := make(chan string, 1)
	addr, _, _, _ := mailSetupWhen(t, "smtp", false, nil, nil, func(p *mailProxy) {
		p.trouble = func(service, remote, how string) { reported <- service + " " + remote + " " + how }
	})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	// No roots at all: the certificate cannot be trusted.
	if err := tls.Client(conn, &tls.Config{ServerName: "mail.example", MinVersion: tls.VersionTLS12}).Handshake(); err == nil {
		t.Fatal("the test client accepted a certificate it cannot know")
	}
	select {
	case got := <-reported:
		if !strings.HasPrefix(got, "SMTP 127.0.0.1 ") {
			t.Fatalf("reported %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was reported")
	}
}
