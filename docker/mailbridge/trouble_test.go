package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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

func TestQuiet(t *testing.T) {
	q := quiet{period: time.Hour}
	if held, ok := q.again("a"); !ok || held != 0 {
		t.Fatalf("the first time: %d, %v", held, ok)
	}
	for range 3 {
		if _, ok := q.again("a"); ok {
			t.Fatal("reported again within the period")
		}
	}
	if _, ok := q.again("b"); !ok {
		t.Fatal("another key was held back")
	}
	q.seen["a"].reported = time.Now().Add(-2 * time.Hour)
	if held, ok := q.again("a"); !ok || held != 3 {
		t.Fatalf("after the period: %d, %v", held, ok)
	}
	if held, ok := q.again("a"); ok || held != 0 {
		t.Fatalf("right after that: %d, %v", held, ok)
	}
}

// What a browser that will not open the web UI leaves behind is said once,
// with the address it used.
func TestWebTrouble(t *testing.T) {
	certPath, keyPath := testCert(t, "mail.example")
	trusted, err := NewCertStore(Config{DataDir: t.TempDir(), TLSCert: certPath, TLSKey: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	if !trusted.Covers("mail.example") || trusted.Covers("old.example") {
		t.Fatal("Covers does not go by the names of the certificate")
	}

	var notices []string
	notify := func(_, format string, args ...any) { notices = append(notices, fmt.Sprintf(format, args...)) }
	public, _ := url.Parse("https://mail.example/")
	w := newWebTrouble(trusted, func() *url.URL { return public }, notify)
	const refused = "remote error: tls: unknown certificate"

	// By IP address, every four seconds, each time from another port.
	for port := 64467; port < 64477; port++ {
		addr := fmt.Sprintf("192.168.1.254:%d", port)
		w.asked.note(addr, "")
		if _, err := fmt.Fprintf(w, "http: TLS handshake error from %s: %s\n", addr, refused); err != nil {
			t.Fatal(err)
		}
	}
	if len(notices) != 1 || !strings.Contains(notices[0], "192.168.1.254") || !strings.Contains(notices[0], "by IP address") ||
		!strings.Contains(notices[0], "https://mail.example/") || strings.Contains(notices[0], "64467") {
		t.Fatalf("a window left open at the IP address: %q", notices)
	}

	notices = nil
	w.asked.note("192.168.1.254:50000", "old.example")
	w.handshake("192.168.1.254:50000", refused)
	if len(notices) != 1 || !strings.Contains(notices[0], "as old.example") || !strings.Contains(notices[0], "mail.example") {
		t.Fatalf("a name the certificate does not cover: %q", notices)
	}

	notices = nil
	w.asked.note("[2001:db8::20]:50000", "mail.example")
	w.handshake("[2001:db8::20]:50000", "remote error: tls: unknown certificate authority")
	if len(notices) != 1 || !strings.Contains(notices[0], "2001:db8::20 ") || !strings.Contains(notices[0], "although") {
		t.Fatalf("the right name and still refused: %q", notices)
	}

	// Not about the certificate, or nothing a notice could help with.
	notices = nil
	for _, msg := range []string{
		"client sent an HTTP request to an HTTPS server",
		"read tcp 172.21.0.2:8080->192.168.1.9:65154: i/o timeout",
		"EOF",
	} {
		w.handshake("192.168.1.9:65154", msg)
	}
	_, _ = io.WriteString(w, "http: superfluous response.WriteHeader call\n")
	if len(notices) != 0 {
		t.Fatalf("notices for nothing: %q", notices)
	}
	if len(w.asked.names) != 0 {
		t.Fatalf("names kept after their handshake ended: %v", w.asked.names)
	}

	// Every browser turns a self-signed certificate down until it is told
	// otherwise: that is for the log, not for a notice.
	selfSigned, err := NewCertStore(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	w = newWebTrouble(selfSigned, func() *url.URL { return nil }, notify)
	w.asked.note("192.168.1.254:50000", "")
	w.handshake("192.168.1.254:50000", refused)
	if len(notices) != 0 {
		t.Fatalf("a notice about the self-signed certificate: %q", notices)
	}
}

// The web server tells webTrouble the name a browser asked for and how the
// handshake ended.
func TestWebTroubleServer(t *testing.T) {
	certPath, keyPath := testCert(t, "mail.example")
	certs, err := NewCertStore(Config{DataDir: t.TempDir(), TLSCert: certPath, TLSKey: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	reported := make(chan string, 4)
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "page") }),
		ReadHeaderTimeout: 5 * time.Second,
	}
	newWebTrouble(certs, func() *url.URL { return nil }, func(_, format string, args ...any) {
		reported <- fmt.Sprintf(format, args...)
	}).watch(srv)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer func() { _ = srv.Close() }()

	// A browser that accepts the certificate gets the page, and no notice.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec
	res, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if string(body) != "page" {
		t.Fatalf("served %q", body)
	}

	// One with no roots at all cannot accept it.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := tls.Client(conn, &tls.Config{ServerName: "old.example", RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}).Handshake(); err == nil {
		t.Fatal("the test client accepted a certificate it cannot know")
	}
	select {
	case got := <-reported:
		if !strings.Contains(got, "127.0.0.1 opened this page as old.example") {
			t.Fatalf("reported %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was reported")
	}
}
