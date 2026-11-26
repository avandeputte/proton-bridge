package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testCert makes a self-signed certificate for the given name in a new
// directory and returns its files.
func testCert(t *testing.T, name string) (certPath, keyPath string) {
	t.Helper()
	certPath, keyPath, err := ensureSelfSigned(Config{DataDir: t.TempDir(), Hostname: name})
	if err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func hasName(info CertInfo, name string) bool {
	for _, n := range info.Names {
		if n == name {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestCertStore(t *testing.T) {
	dir := t.TempDir()
	store, err := NewCertStore(Config{DataDir: dir, Hostname: "first.example"})
	if err != nil {
		t.Fatal(err)
	}
	if info := store.Info(); info.Origin != certSelfSigned || !hasName(info, "first.example") {
		t.Fatalf("unexpected first certificate: %+v", info)
	}

	var changes atomic.Int32
	store.OnChange(func() { changes.Add(1) })

	// A pair that does not match changes nothing.
	certA, keyA := testCert(t, "a.example")
	certB, keyB := testCert(t, "b.example")
	if err := store.Load(certA, keyB, certOwn); err == nil {
		t.Fatal("a certificate with another certificate's key was accepted")
	}
	if info := store.Info(); !hasName(info, "first.example") {
		t.Fatalf("a failed load changed the certificate: %+v", info)
	}

	if err := store.Load(certA, keyA, certOwn); err != nil {
		t.Fatal(err)
	}
	if info := store.Info(); info.Origin != certOwn || !hasName(info, "a.example") {
		t.Fatalf("unexpected certificate after load: %+v", info)
	}
	waitFor(t, "the change to be announced", func() bool { return changes.Load() == 1 })

	// The copy on disk, which Dovecot reads, is the one in use.
	activeCert, activeKey := store.Paths()
	pair, err := tls.LoadX509KeyPair(activeCert, activeKey)
	if err != nil {
		t.Fatal(err)
	}
	served, err := store.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pair.Certificate[0], served.Certificate[0]) {
		t.Fatal("the files do not hold the certificate in use")
	}

	// Loading the same certificate again is not a change.
	if err := store.Load(certA, keyA, certOwn); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := changes.Load(); n != 1 {
		t.Fatalf("expected 1 change, got %d", n)
	}

	// Watch picks up a certificate that is renewed in place, also when the
	// two files are replaced one after the other.
	old := certWatchInterval
	certWatchInterval = 20 * time.Millisecond
	defer func() { certWatchInterval = old }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watched := make(chan struct{})
	go func() {
		store.Watch(ctx, certA, keyA, certOwn)
		close(watched)
	}()
	time.Sleep(60 * time.Millisecond)
	copyFile(t, certB, certA)
	time.Sleep(100 * time.Millisecond)
	if info := store.Info(); !hasName(info, "a.example") {
		t.Fatalf("half a renewal was put to use: %+v", info)
	}
	copyFile(t, keyB, keyA)
	waitFor(t, "the renewed certificate", func() bool { return hasName(store.Info(), "b.example") })
	cancel()
	<-watched
}

// --- fake mail servers that behave like bridge ---------------------------------

type fakeMail struct {
	addr string
	// What arrived over TLS, to check that sessions are passed on intact.
	mu   sync.Mutex
	seen []string
}

func (f *fakeMail) saw(line string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, strings.TrimSpace(line))
}

func (f *fakeMail) sawLine(line string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.seen {
		if s == line {
			return true
		}
	}
	return false
}

func startFakeMail(t *testing.T, proto string, cert tls.Certificate, implicit bool) *fakeMail {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	f := &fakeMail{addr: ln.Addr().String()}
	conf := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				secure := false
				if implicit {
					conn = tls.Server(conn, conf)
					secure = true
				}
				if proto == "smtp" {
					f.smtp(conn, conf, secure)
				} else {
					f.imap(conn, conf, secure)
				}
			}()
		}
	}()
	return f
}

func (f *fakeMail) smtp(conn net.Conn, conf *tls.Config, secure bool) {
	r := bufio.NewReader(conn)
	say := func(s string) { _, _ = conn.Write([]byte(s)) }
	say("220 fake ESMTP ready\r\n")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		if secure {
			f.saw(line)
		}
		verb, _, _ := strings.Cut(strings.ToUpper(strings.TrimSpace(line)), " ")
		switch {
		case verb == "EHLO" && !secure:
			say("250-fake\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n")
		case verb == "EHLO":
			say("250-fake\r\n250 AUTH PLAIN LOGIN\r\n")
		case verb == "STARTTLS" && !secure:
			say("220 go ahead\r\n")
			conn = tls.Server(conn, conf)
			r = bufio.NewReader(conn)
			secure = true
		case verb == "AUTH" && secure:
			say("235 2.0.0 welcome\r\n")
		case verb == "AUTH":
			// Like bridge, which allows it. The proxy must not let it through.
			say("235 2.0.0 welcome without encryption\r\n")
		case verb == "QUIT":
			say("221 bye\r\n")
			return
		default:
			say("250 ok\r\n")
		}
	}
}

func (f *fakeMail) imap(conn net.Conn, conf *tls.Config, secure bool) {
	r := bufio.NewReader(conn)
	say := func(s string) { _, _ = conn.Write([]byte(s)) }
	say("* OK [CAPABILITY IMAP4rev1 STARTTLS] fake ready\r\n")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		if secure {
			f.saw(line)
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			say("* BAD\r\n")
			continue
		}
		tag, verb := fields[0], strings.ToUpper(fields[1])
		switch {
		case verb == "CAPABILITY" && !secure:
			say("* CAPABILITY IMAP4rev1 STARTTLS\r\n" + tag + " OK done\r\n")
		case verb == "CAPABILITY":
			say("* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n" + tag + " OK done\r\n")
		case verb == "STARTTLS" && !secure:
			say(tag + " OK begin\r\n")
			conn = tls.Server(conn, conf)
			r = bufio.NewReader(conn)
			secure = true
		case verb == "LOGIN":
			say(tag + " OK logged in\r\n")
		case verb == "LOGOUT":
			say("* BYE\r\n" + tag + " OK\r\n")
			return
		default:
			say(tag + " OK\r\n")
		}
	}
}

// mailClient is the mail client's end of a test session.
type mailClient struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

func dialMail(t *testing.T, addr string) *mailClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	return &mailClient{t: t, conn: conn, r: bufio.NewReader(conn)}
}

func (c *mailClient) send(line string) {
	c.t.Helper()
	if _, err := c.conn.Write([]byte(line + "\r\n")); err != nil {
		c.t.Fatal(err)
	}
}

// expect reads lines up to and including the one that starts with prefix.
func (c *mailClient) expect(prefix string) string {
	c.t.Helper()
	var got []string
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			c.t.Fatalf("waiting for %q: %v (got %q)", prefix, err, got)
		}
		got = append(got, line)
		if strings.HasPrefix(line, prefix) {
			return strings.Join(got, "")
		}
		if len(line) >= 4 && line[3] == '-' || strings.HasPrefix(line, "* ") {
			continue // more lines of the same reply
		}
		c.t.Fatalf("expected %q, got %q", prefix, got)
	}
}

// startTLS switches to TLS and insists on the certificate from trusted, for name.
func (c *mailClient) startTLS(trustedCertPath, name string) {
	c.t.Helper()
	pem, err := os.ReadFile(trustedCertPath)
	if err != nil {
		c.t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	conn := tls.Client(c.conn, &tls.Config{RootCAs: pool, ServerName: name, MinVersion: tls.VersionTLS12})
	if err := conn.Handshake(); err != nil {
		c.t.Fatalf("TLS with the proxy: %v", err)
	}
	c.conn, c.r = conn, bufio.NewReader(conn)
}

// mailSetup runs a fake bridge and a proxy in front of it. The proxy presents
// a certificate for mail.example; bridge has its own.
func mailSetup(t *testing.T, proto string, implicit bool, pin func(bridgeCertPath string) ([]byte, error)) (proxyAddr, trusted string, upstream *fakeMail) {
	t.Helper()
	proxyAddr, trusted, _, upstream = mailSetupWhen(t, proto, implicit, pin, nil)
	return proxyAddr, trusted, upstream
}

// mailSetupWhen is mailSetup with a proxy that only answers for itself
// while active says so.
func mailSetupWhen(t *testing.T, proto string, implicit bool, pin func(bridgeCertPath string) ([]byte, error), active func() bool) (proxyAddr, trusted, bridgeCert string, upstream *fakeMail) {
	t.Helper()
	bridgeCert, bridgeKey := testCert(t, "bridge.internal")
	pair, err := tls.LoadX509KeyPair(bridgeCert, bridgeKey)
	if err != nil {
		t.Fatal(err)
	}
	upstream = startFakeMail(t, proto, pair, implicit)

	trusted, trustedKey := testCert(t, "mail.example")
	store, err := NewCertStore(Config{DataDir: t.TempDir(), TLSCert: trusted, TLSKey: trustedKey})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr = ln.Addr().String()
	_ = ln.Close()

	if pin == nil {
		pin = func(path string) ([]byte, error) { return os.ReadFile(path) }
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	startMailProxy(ctx, &wg, &mailProxy{
		name: strings.ToUpper(proto), proto: proto, certs: store,
		upstream: func() (string, bool) { return upstream.addr, implicit },
		pinned:   func() ([]byte, error) { return pin(bridgeCert) },
		active:   active,
	}, proxyAddr)
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	return proxyAddr, trusted, bridgeCert, upstream
}

// Without a certificate that clients trust there is nothing to gain from
// answering in bridge's place: the session is passed on as it is, and the
// client sees bridge's own certificate, as it did before there was a proxy.
func TestMailProxyStandsAsideWithoutCertificate(t *testing.T) {
	var active atomic.Bool
	addr, trusted, bridgeCert, upstream := mailSetupWhen(t, "smtp", false, nil, active.Load)

	c := dialMail(t, addr)
	c.expect("220 ")
	c.send("EHLO client.example")
	c.expect("250 ")
	c.send("STARTTLS")
	c.expect("220 ")
	c.startTLS(bridgeCert, "bridge.internal")
	c.send("EHLO client.example")
	c.expect("250 ")
	c.send("AUTH PLAIN AHVzZXIAcGFzcw==")
	c.expect("235 ")
	c.send("QUIT")
	c.expect("221 ")
	if !upstream.sawLine("AUTH PLAIN AHVzZXIAcGFzcw==") {
		t.Fatalf("the session did not reach bridge intact: %q", upstream.seen)
	}

	// Once there is a certificate, new sessions get it. No restart needed.
	active.Store(true)
	c = dialMail(t, addr)
	c.expect("220 ")
	c.send("EHLO client.example")
	c.expect("250 ")
	c.send("STARTTLS")
	c.expect("220 ")
	c.startTLS(trusted, "mail.example")
	c.send("QUIT")
	c.expect("221 ")
}

func TestMailProxySMTP(t *testing.T) {
	addr, trusted, upstream := mailSetup(t, "smtp", false, nil)

	c := dialMail(t, addr)
	c.expect("220 ")
	c.send("EHLO client.example")
	if reply := c.expect("250 "); !strings.Contains(reply, "STARTTLS") {
		t.Fatalf("STARTTLS is not offered: %q", reply)
	}
	// Bridge would take a password without encryption. The proxy does not pass it on.
	c.send("AUTH PLAIN AHVzZXIAcGFzcw==")
	c.expect("530 ")
	c.send("MAIL FROM:<a@example.com>")
	c.expect("530 ")
	c.send("STARTTLS")
	c.expect("220 ")
	c.startTLS(trusted, "mail.example")

	c.send("EHLO client.example")
	if reply := c.expect("250 "); strings.Contains(reply, "STARTTLS") {
		t.Fatalf("STARTTLS is still offered after TLS: %q", reply)
	}
	c.send("AUTH PLAIN AHVzZXIAcGFzcw==")
	c.expect("235 ")
	c.send("QUIT")
	c.expect("221 ")

	if !upstream.sawLine("AUTH PLAIN AHVzZXIAcGFzcw==") {
		t.Fatalf("the session did not reach bridge intact: %q", upstream.seen)
	}
}

func TestMailProxyIMAP(t *testing.T) {
	addr, trusted, upstream := mailSetup(t, "imap", false, nil)

	c := dialMail(t, addr)
	c.expect("* OK")
	c.send("a1 CAPABILITY")
	c.expect("a1 OK")
	c.send("a2 LOGIN user pass")
	c.expect("a2 NO")
	c.send("a3 STARTTLS")
	c.expect("a3 OK")
	c.startTLS(trusted, "mail.example")

	c.send("a4 LOGIN user pass")
	c.expect("a4 OK")
	c.send("a5 LOGOUT")
	c.expect("a5 OK")

	if !upstream.sawLine("a4 LOGIN user pass") {
		t.Fatalf("the session did not reach bridge intact: %q", upstream.seen)
	}
	if upstream.sawLine("a2 LOGIN user pass") {
		t.Fatal("a login without encryption was passed on to bridge")
	}
}

// With SSL/TLS instead of STARTTLS, TLS starts at the first byte on both sides.
func TestMailProxyImplicitTLS(t *testing.T) {
	for _, proto := range []string{"smtp", "imap"} {
		t.Run(proto, func(t *testing.T) {
			addr, trusted, upstream := mailSetup(t, proto, true, nil)
			c := dialMail(t, addr)
			c.startTLS(trusted, "mail.example")
			if proto == "smtp" {
				c.expect("220 ")
				c.send("EHLO client.example")
				c.expect("250 ")
				if !upstream.sawLine("EHLO client.example") {
					t.Fatalf("the session did not reach bridge: %q", upstream.seen)
				}
			} else {
				c.expect("* OK")
				c.send("a1 LOGIN user pass")
				c.expect("a1 OK")
			}
		})
	}
}

// The session with bridge is only trusted with the certificate bridge exported.
func TestMailProxyPinsBridge(t *testing.T) {
	other, _ := testCert(t, "someone-else.internal")
	addr, _, upstream := mailSetup(t, "smtp", false, func(string) ([]byte, error) { return os.ReadFile(other) })

	c := dialMail(t, addr)
	c.expect("220 ")
	c.send("EHLO client.example")
	c.expect("250 ")
	c.send("STARTTLS")
	c.expect("454 ")
	if len(upstream.seen) != 0 {
		t.Fatalf("data was sent to a server that is not bridge: %q", upstream.seen)
	}
}

// --- Let's Encrypt ---------------------------------------------------------------

// fakeLego stands in for the lego command: it logs how it was called and, if
// told to succeed, delivers the certificate from $FAKE_CERT and $FAKE_KEY.
const fakeLego = `#!/bin/sh
case " $* " in
  *" dnshelp -c fake "*)
    echo "Configuration for Fake DNS."
    echo "Code:   'fake'"
    echo
    echo "Credentials:"
    echo '  - "FAKE_TOKEN":  API token'
    echo '  - "FAKE_USER":   Account name'
    echo
    echo "Additional Configuration:"
    echo '  - "FAKE_TTL":  The TTL of the TXT record (Default: 120)'
    echo
    echo "More information: https://example.org/dns/fake"
    exit 0 ;;
  *" dnshelp -c "*) echo '"that" is not yet supported' >&2; exit 1 ;;
  *" dnshelp "*) printf 'Supported DNS providers:\n  exec, fake, manual, other\n\nMore information: https://example.org/dns\n'; exit 0 ;;
esac
echo "$@" >> "$FAKE_LOG"
echo "token=$FAKE_TOKEN ttl=$FAKE_TTL password=$MAILBRIDGE_PASSWORD" >> "$FAKE_LOG.env"
while [ $# -gt 1 ]; do
  case "$1" in
    --path) path="$2" ;;
    --domains) [ -n "$domain" ] || domain="$2" ;;
  esac
  shift
done
if [ -e "$FAKE_FAIL" ]; then
  echo "some progress"
  echo "acme: error presenting token: the DNS provider said no" >&2
  exit 1
fi
[ "$1" = run ] || [ -e "$FAKE_RENEW" ] || exit 0
mkdir -p "$path/certificates"
name=$(echo "$domain" | sed 's/\*/_/')
cp "$FAKE_KEY" "$path/certificates/$name.key"
cp "$FAKE_CERT" "$path/certificates/$name.crt"
`

func acmeState(a *ACME) string {
	st, _ := a.Status()
	return st.State
}

func TestACME(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "lego")
	if err := os.WriteFile(bin, []byte(fakeLego), 0o700); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	logPath, failPath, renewPath := filepath.Join(dir, "log"), filepath.Join(dir, "fail"), filepath.Join(dir, "renew")
	cert1, key1 := testCert(t, "mail.example")
	cert2, key2 := testCert(t, "mail.example")
	liveCert, liveKey := filepath.Join(dir, "live.crt"), filepath.Join(dir, "live.key")
	copyFile(t, cert1, liveCert)
	copyFile(t, key1, liveKey)
	for k, v := range map[string]string{
		"FAKE_LOG": logPath, "FAKE_FAIL": failPath, "FAKE_RENEW": renewPath, "FAKE_CERT": liveCert, "FAKE_KEY": liveKey,
		"MAILBRIDGE_PASSWORD": "not for lego",
	} {
		t.Setenv(k, v)
	}

	oldRetry := acmeRetry
	acmeRetry = []time.Duration{50 * time.Millisecond}
	defer func() { acmeRetry = oldRetry }()

	cfg := Config{
		DataDir: filepath.Join(dir, "data"), ACMEBin: bin, ACMEServer: acmeStaging, ACMEDNS: "exec",
		ACMEDomains: []string{"*.mail.example", "mail.example"}, ACMEEmail: "admin@mail.example", ACMEResolvers: []string{"1.1.1.1:53"},
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewCertStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	selfSigned, _ := store.GetCertificate(nil)

	// --- first run: lego fails, then succeeds ---
	if err := os.WriteFile(failPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	acme := NewACME(cfg, store)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		acme.Run(ctx)
		close(done)
	}()

	waitFor(t, "the failure to be reported", func() bool { return acmeState(acme) == "error" })
	st, _ := acme.Status()
	if !strings.Contains(st.Message, "the DNS provider said no") || st.Next.IsZero() {
		t.Fatalf("unexpected status after a failure: %+v", st)
	}
	if now, _ := store.GetCertificate(nil); now != selfSigned {
		t.Fatal("the certificate changed although lego failed")
	}

	if err := os.Remove(failPath); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the certificate", func() bool { return acmeState(acme) == "ok" })
	if info := store.Info(); info.Origin != certLetsEncrypt || !hasName(info, "mail.example") {
		t.Fatalf("unexpected certificate: %+v", info)
	}
	first, _ := store.GetCertificate(nil)
	cancel()
	<-done

	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("--accept-tos --path %s --server %s --dns exec --domains *.mail.example --domains mail.example --email admin@mail.example --dns.resolvers 1.1.1.1:53 run",
		filepath.Join(cfg.DataDir, "acme", "acme-staging-v02.api.letsencrypt.org"), acmeStaging)
	for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
		if line != want {
			t.Fatalf("lego was called with\n%s\nexpected\n%s", line, want)
		}
	}

	// --- next start: the stored certificate is used at once, then renewed ---
	store, err = NewCertStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	copyFile(t, cert2, liveCert)
	copyFile(t, key2, liveKey)
	if err := os.WriteFile(renewPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(logPath); err != nil {
		t.Fatal(err)
	}
	acme = NewACME(cfg, store)
	acme.UseStored()
	if stored, _ := store.GetCertificate(nil); !bytes.Equal(stored.Certificate[0], first.Certificate[0]) {
		t.Fatal("the stored certificate was not put to use at start-up")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	done = make(chan struct{})
	go func() {
		acme.Run(ctx)
		close(done)
	}()
	waitFor(t, "the renewal", func() bool { return acmeState(acme) == "ok" })
	renewed, _ := store.GetCertificate(nil)
	if bytes.Equal(renewed.Certificate[0], first.Certificate[0]) {
		t.Fatal("the renewed certificate was not put to use")
	}
	cancel()
	<-done

	calls, err = os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(strings.TrimSpace(string(calls)), " renew --dynamic --no-random-sleep --force-cert-domains") {
		t.Fatalf("expected a renewal, lego was called with\n%s", calls)
	}

	// --- another certificate authority starts from scratch ---
	cfg.ACMEServer = acmeProduction
	if other := NewACME(cfg, store); other.have(other.Settings()) {
		t.Fatal("the staging certificate was taken for a production one")
	}
}

func TestValidDomain(t *testing.T) {
	for d, want := range map[string]bool{
		"mail.example.com": true, "*.example.com": true, "a-b.example.co.uk": true,
		"": false, "localhost": false, "*.": false, "mail..com": false, "-a.example.com": false,
		"mail.example.com;rm": false, "*.*.example.com": false, "--help.example.com": false, "192.168.1.5": false,
	} {
		if got := validDomain(d); got != want {
			t.Errorf("validDomain(%q) = %v, want %v", d, got, want)
		}
	}
}
