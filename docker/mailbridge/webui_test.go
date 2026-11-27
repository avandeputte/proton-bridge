package main

import (
	"bufio"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Let's Encrypt set up in the web UI --------------------------------------------

func TestACMEConfigure(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "lego")
	if err := os.WriteFile(bin, []byte(fakeLego), 0o700); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "log")
	cert, key := testCert(t, "mail.example")
	for k, v := range map[string]string{
		"FAKE_LOG": logPath, "FAKE_FAIL": filepath.Join(dir, "fail"), "FAKE_RENEW": filepath.Join(dir, "renew"),
		"FAKE_CERT": cert, "FAKE_KEY": key, "MAILBRIDGE_PASSWORD": "not for lego",
	} {
		t.Setenv(k, v)
	}

	cfg := Config{DataDir: filepath.Join(dir, "data"), ACMEBin: bin, ACMEServer: "https://ca.test/dir"}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewCertStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	acme := NewACME(cfg, store)
	if _, on := acme.Status(); on || acme.Locked() != "" {
		t.Fatal("Let's Encrypt is on or locked before anything was set up")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		acme.Run(ctx)
		close(done)
	}()

	providers, err := acme.Providers(ctx)
	if err != nil || strings.Join(providers, ",") != "fake,other" {
		t.Fatalf("providers = %v, %v", providers, err)
	}
	info, err := acme.Provider(ctx, "fake")
	if err != nil || info.Name != "Fake DNS" || len(info.Credentials) != 2 || len(info.Options) != 1 ||
		info.Credentials[0] != (ProviderVariable{"FAKE_TOKEN", "API token"}) || info.URL != "https://example.org/dns/fake" {
		t.Fatalf("provider = %+v, %v", info, err)
	}

	// What must not get through.
	good := ACMESettings{Domains: []string{" Mail.Example "}, DNS: "fake", Variables: map[string]string{"FAKE_TOKEN": "s3cret"}}
	for name, bad := range map[string]func(*ACMESettings){
		"not a domain":            func(s *ACMESettings) { s.Domains = []string{"mail example"} },
		"an option as a domain":   func(s *ACMESettings) { s.Domains = []string{"--help.example.com"} },
		"a provider running code": func(s *ACMESettings) { s.DNS = "exec" },
		"an unknown provider":     func(s *ACMESettings) { s.DNS = "nosuch" },
		"an option as a provider": func(s *ACMESettings) { s.DNS = "--http" },
		"a foreign variable":      func(s *ACMESettings) { s.Variables = map[string]string{"LD_PRELOAD": "/tmp/x.so"} },
		"another foreign one":     func(s *ACMESettings) { s.Variables = map[string]string{"PATH": "/tmp"} },
		"a value with a newline":  func(s *ACMESettings) { s.Variables = map[string]string{"FAKE_TOKEN": "a\nb"} },
		"a bad contact address":   func(s *ACMESettings) { s.Email = "--server=x" },
		"an option as a resolver": func(s *ACMESettings) { s.Resolvers = []string{"--dns.resolvers x"} },
	} {
		s := good
		bad(&s)
		if err := acme.Configure(ctx, s, nil); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, on := acme.Status(); on {
		t.Fatal("refused settings were put to use")
	}

	// --- the first certificate ---
	good.Variables["FAKE_TTL_FILE"] = "/run/secrets/ttl"
	if err := acme.Configure(ctx, good, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the certificate", func() bool { return acmeState(acme) == "ok" })
	if info := store.Info(); info.Origin != certLetsEncrypt || !store.Trusted() || store.Hostname() != info.Names[0] {
		t.Fatalf("unexpected certificate: %+v", info)
	}
	if fi, err := os.Stat(filepath.Join(cfg.DataDir, "acme.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the settings file: %v, %v", fi, err)
	}
	env, _ := os.ReadFile(logPath + ".env")
	if got := strings.TrimSpace(string(env)); got != "token=s3cret ttl= password=" {
		t.Fatalf("lego ran with %q", got)
	}
	calls, _ := os.ReadFile(logPath)
	want := "--accept-tos --path " + filepath.Join(cfg.DataDir, "acme", "ca.test") + " --server https://ca.test/dir --dns fake --domains mail.example run"
	if got := strings.TrimSpace(string(calls)); got != want {
		t.Fatalf("lego was called with\n%s\nexpected\n%s", got, want)
	}

	// --- changed in the web UI, which does not know the token: it is kept ---
	next := ACMESettings{Domains: []string{"mail.example"}, DNS: "fake", Staging: true, Email: "me@mail.example",
		Resolvers: []string{"1.1.1.1"}, Variables: map[string]string{"FAKE_TTL": "60"}}
	if err := acme.Configure(ctx, next, []string{"FAKE_TOKEN"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the test certificate", func() bool { st, _ := acme.Status(); return st.State == "ok" && st.Staging })
	got := acme.Settings()
	if got.Variables["FAKE_TOKEN"] != "s3cret" || got.Variables["FAKE_TTL"] != "60" || len(got.Variables) != 2 || got.Resolvers[0] != "1.1.1.1:53" {
		t.Fatalf("settings after the change: %+v", got)
	}
	calls, _ = os.ReadFile(logPath)
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	want = "--accept-tos --path " + filepath.Join(cfg.DataDir, "acme", "acme-staging-v02.api.letsencrypt.org") + " --server " + acmeStaging +
		" --dns fake --domains mail.example --email me@mail.example --dns.resolvers 1.1.1.1:53 run"
	if lines[len(lines)-1] != want {
		t.Fatalf("lego was called with\n%s\nexpected\n%s", lines[len(lines)-1], want)
	}

	// --- a restart finds the settings again ---
	if again := NewACME(cfg, store).Settings(); again.Variables["FAKE_TOKEN"] != "s3cret" || !again.Staging {
		t.Fatalf("settings after a restart: %+v", again)
	}

	// --- turned off: back to the self-signed certificate ---
	if err := acme.Configure(ctx, ACMESettings{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, on := acme.Status(); on || store.Trusted() {
		t.Fatalf("still on after turning it off: %+v", store.Info())
	}
	cancel()
	<-done

	// --- the web UI stays out of what the environment decides ---
	fromEnv := cfg
	fromEnv.ACMEDomains, fromEnv.ACMEDNS = []string{"mail.example"}, "fake"
	if a := NewACME(fromEnv, store); a.Locked() != "environment" || a.Configure(ctx, good, nil) == nil {
		t.Fatal("the web UI could change settings made in the environment")
	}
	own := cfg
	own.TLSCert, own.TLSKey = cert, key
	if a := NewACME(own, store); a.Locked() != "certificate" || a.Configure(ctx, good, nil) == nil {
		t.Fatal("the web UI could replace the user's own certificate")
	}
}

// --- ports ---------------------------------------------------------------------------

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// greeting connects to a port and returns the first line it is sent.
func greeting(port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	line, _ := bufio.NewReader(conn).ReadString('\n')
	return strings.TrimSpace(line)
}

func testPorts(t *testing.T, ctx context.Context, wg *sync.WaitGroup, cfg Config, services ...string) *Ports {
	t.Helper()
	p := NewPorts(ctx, wg, cfg)
	for _, service := range services {
		p.Handle(service, func(_ context.Context, conn net.Conn) {
			_, _ = io.WriteString(conn, service+"\n")
			_ = conn.Close()
		})
	}
	return p
}

func TestPorts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()

	fixed := freePort(t)
	cfg := Config{DataDir: t.TempDir(), IMAPListen: []string{fmt.Sprintf("127.0.0.1:%d", fixed)}, IMAPPort: "143", SMTPPort: "587"}
	p := testPorts(t, ctx, &wg, cfg, svcIMAP, svcSMTP)
	if problems := p.Start(); len(problems) != 0 {
		t.Fatal(problems)
	}
	if greeting(fixed) != "imap" || p.Shown(svcIMAP) != "143" || p.Shown(svcIMAPS) != "" {
		t.Fatal("the port from the environment is not served as configured")
	}

	a, b, c := freePort(t), freePort(t), freePort(t)
	if err := p.Set(PortSettings{IMAP: a, SMTP: c}); err != nil {
		t.Fatal(err)
	}
	if greeting(a) != "imap" || greeting(c) != "smtp" || greeting(fixed) != "imap" {
		t.Fatal("the new ports are not served, or the default one was closed")
	}
	if p.Shown(svcIMAP) != fmt.Sprint(a) || p.Shown(svcSMTP) != fmt.Sprint(c) {
		t.Fatalf("shown ports: %s, %s", p.Shown(svcIMAP), p.Shown(svcSMTP))
	}

	// Moving one service leaves the other alone.
	if err := p.Set(PortSettings{IMAP: b, SMTP: c}); err != nil {
		t.Fatal(err)
	}
	if greeting(a) != "" || greeting(b) != "imap" || greeting(c) != "smtp" {
		t.Fatal("moving IMAP did not close the old port, open the new one and keep SMTP")
	}

	// Refused changes change nothing.
	for name, bad := range map[string]PortSettings{
		"a port that is taken":             {IMAP: c, SMTP: c},
		"a number that is not a port":      {IMAP: 70000, SMTP: c},
		"a negative number":                {IMAP: -1, SMTP: c},
		"a service that is not offered":    {IMAP: b, IMAPS: a, SMTP: c},
		"one good and one impossible port": {IMAP: a, SMTP: b},
	} {
		if err := p.Set(bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if greeting(a) != "" || greeting(b) != "imap" || greeting(c) != "smtp" || p.Settings() != (PortSettings{IMAP: b, SMTP: c}) {
		t.Fatalf("a refused change left its mark: %+v", p.Settings())
	}

	// The port that the environment set needs no second listener.
	if err := p.Set(PortSettings{IMAP: fixed, SMTP: c}); err != nil {
		t.Fatal(err)
	}
	if greeting(b) != "" || greeting(fixed) != "imap" {
		t.Fatal("going back to the default port did not work")
	}

	// A restart opens the stored ports again, on the same interface.
	cancel()
	wg.Wait()
	ctx2, cancel2 := context.WithCancel(context.Background())
	var wg2 sync.WaitGroup
	defer func() {
		cancel2()
		wg2.Wait()
	}()
	again := testPorts(t, ctx2, &wg2, cfg, svcIMAP, svcSMTP)
	if problems := again.Start(); len(problems) != 0 {
		t.Fatal(problems)
	}
	if greeting(c) != "smtp" || again.Settings().SMTP != c {
		t.Fatal("the stored port is not served after a restart")
	}

	// A stored port that cannot be opened is reported, not fatal.
	blocker, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Close() }()
	taken := blocker.Addr().(*net.TCPAddr).Port
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ports.json"), []byte(fmt.Sprintf(`{"smtp": %d}`, taken)), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := testPorts(t, ctx2, &wg2, Config{DataDir: dir}, svcSMTP)
	if problems := broken.Start(); len(problems) != 1 || !strings.Contains(problems[0], fmt.Sprint(taken)) {
		t.Fatalf("problems = %q", problems)
	}
}

// --- Apple configuration profile -----------------------------------------------------

// plistDict reads the top level of a property list into key/value pairs,
// which also proves that it is well-formed XML.
func plistStrings(t *testing.T, data []byte) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	var key string
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("the profile is not well-formed: %v", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "key":
			if err := dec.DecodeElement(&key, &start); err != nil {
				t.Fatal(err)
			}
		case "string", "integer":
			var v string
			if err := dec.DecodeElement(&v, &start); err != nil {
				t.Fatal(err)
			}
			out[key] = append(out[key], v)
		case "true":
			out[key] = append(out[key], "true")
		}
	}
}

func TestAppleMailProfile(t *testing.T) {
	accounts := []profileAccount{{"jane@example.com", `p<&>"w`}, {"jane.doe@example.com", `p<&>"w`}}
	data := appleMailProfile("mail.example.com", 993, 587, accounts)
	got := plistStrings(t, data)

	for key, want := range map[string][]string{
		"EmailAddress":                     {"jane@example.com", "jane.doe@example.com"},
		"IncomingMailServerUsername":       {"jane@example.com", "jane.doe@example.com"},
		"IncomingPassword":                 {`p<&>"w`, `p<&>"w`},
		"OutgoingPassword":                 {`p<&>"w`, `p<&>"w`},
		"IncomingMailServerHostName":       {"mail.example.com", "mail.example.com"},
		"OutgoingMailServerHostName":       {"mail.example.com", "mail.example.com"},
		"IncomingMailServerPortNumber":     {"993", "993"},
		"OutgoingMailServerPortNumber":     {"587", "587"},
		"IncomingMailServerUseSSL":         {"true", "true"},
		"OutgoingMailServerUseSSL":         {"true", "true"},
		"EmailAccountType":                 {"EmailTypeIMAP", "EmailTypeIMAP"},
		"PayloadType":                      {"com.apple.mail.managed", "com.apple.mail.managed", "Configuration"},
		"IncomingMailServerAuthentication": {"EmailAuthPassword", "EmailAuthPassword"},
	} {
		if strings.Join(got[key], "|") != strings.Join(want, "|") {
			t.Errorf("%s = %q, want %q", key, got[key], want)
		}
	}

	// Three payloads, three identifiers, and the same ones every time, so
	// that a newer profile replaces the one installed before.
	ids := got["PayloadUUID"]
	if len(ids) != 3 || ids[0] == ids[1] || ids[1] == ids[2] || ids[0] == ids[2] {
		t.Fatalf("PayloadUUID = %q", ids)
	}
	for _, id := range ids {
		if len(id) != 36 || strings.Count(id, "-") != 4 {
			t.Errorf("%q is not a UUID", id)
		}
	}
	if string(appleMailProfile("mail.example.com", 993, 587, accounts)) != string(data) {
		t.Error("the same account gives a different profile the second time")
	}
	if other := plistStrings(t, appleMailProfile("other.example.com", 993, 587, accounts)); other["PayloadUUID"][0] == ids[0] {
		t.Error("another server gives the same identifier")
	}
}

// --- the web UI itself -------------------------------------------------------------------

type webTest struct {
	t       *testing.T
	s       *server
	handler http.Handler
	cookie  *http.Cookie
}

func newWebTest(t *testing.T, cfg Config) *webTest {
	t.Helper()
	cfg.DataDir = t.TempDir()
	cfg.Password = "correct horse battery"
	if cfg.ACMEServer == "" {
		cfg.ACMEServer = acmeProduction
	}
	auth, err := NewAuth(cfg)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := NewCertStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	ports := testPorts(t, ctx, &wg, cfg, svcIMAP, svcSMTP)
	s := &server{cfg: cfg, auth: auth, bridge: NewBridge(cfg), certs: certs, acme: NewACME(cfg, certs), ports: ports, public: NewPublic(cfg)}
	return &webTest{t: t, s: s, handler: s.routes()}
}

func (w *webTest) do(method, target, body string, header ...string) *http.Response {
	w.t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set(csrfHeader, "1")
	if w.cookie != nil {
		req.AddCookie(w.cookie)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	w.handler.ServeHTTP(rec, req)
	return rec.Result()
}

func (w *webTest) signIn(target string, header ...string) *http.Response {
	w.t.Helper()
	res := w.do("POST", target, `{"password":"correct horse battery"}`, header...)
	for _, c := range res.Cookies() {
		if c.Name == sessionCookie {
			w.cookie = c
		}
	}
	return res
}

func TestWebBehindReverseProxy(t *testing.T) {
	public, _ := url.Parse("https://home.example/mailbridge")
	w := newWebTest(t, Config{TLSMode: "off", PublicURL: public})

	if res := w.do("GET", "/mailbridge", ""); res.StatusCode != http.StatusPermanentRedirect || res.Header.Get("Location") != "/mailbridge/" {
		t.Fatalf("GET /mailbridge: %d to %q", res.StatusCode, res.Header.Get("Location"))
	}
	// The page is found whether the proxy passes the prefix on or cuts it off.
	for _, target := range []string{"/mailbridge/", "/", "/mailbridge/app.js", "/app.js"} {
		if res := w.do("GET", target, ""); res.StatusCode != http.StatusOK {
			t.Errorf("GET %s: %d", target, res.StatusCode)
		}
	}

	// Another site cannot send the header that every change has to carry.
	if res := w.signIn("/mailbridge/api/session", csrfHeader, ""); res.StatusCode != http.StatusForbidden || w.cookie != nil {
		t.Fatalf("sign-in without the header: %d", res.StatusCode)
	}

	// The page says where the browser sees it, and the cookie is good for there.
	if res := w.signIn("/mailbridge/api/session", "Origin", "https://home.example", csrfHeader, "/mailbridge/"); res.StatusCode != http.StatusOK || w.cookie == nil {
		t.Fatalf("sign-in through the proxy: %d", res.StatusCode)
	}
	if !w.cookie.Secure || w.cookie.Path != "/mailbridge/" || !w.cookie.HttpOnly {
		t.Fatalf("session cookie: %+v", w.cookie)
	}
	if res := w.do("GET", "/api/state", ""); res.StatusCode != http.StatusOK {
		t.Fatalf("state with the prefix cut off: %d", res.StatusCode)
	}
	// Reached directly, by the address of the container, the page still
	// works, and without TLS there the cookie must not ask for it.
	w.cookie = nil
	if res := w.signIn("/api/session", "Origin", "http://example.com", csrfHeader, "/"); res.StatusCode != http.StatusOK || w.cookie == nil {
		t.Fatalf("sign-in at the container's own address: %d", res.StatusCode)
	}
	if w.cookie.Secure || w.cookie.Path != "/" {
		t.Fatalf("session cookie at the container's own address: %+v", w.cookie)
	}
	if res := w.do("POST", "/api/addresses", `{}`, "Origin", "http://example.com"); res.StatusCode != http.StatusOK {
		t.Fatalf("a change from the page itself, reached directly: %d", res.StatusCode)
	}
}

func TestWebPublicAddresses(t *testing.T) {
	w := newWebTest(t, Config{TLSMode: "off", Hostname: "nas.lan", IMAPPort: "143", SMTPPort: "587"})
	b := w.s.bridge
	b.status = "running"
	b.users = []User{{ID: "u1", Username: "jane@example.com", State: "connected", Password: "bridgepass", Addresses: []string{"jane@example.com"}}}
	w.signIn("/api/session")

	state := func() string {
		t.Helper()
		res := w.do("GET", "/api/state", "")
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("state: %d %s", res.StatusCode, body)
		}
		return string(body)
	}
	save := func(body string, header ...string) int {
		t.Helper()
		return w.do("POST", "/api/addresses", body, header...).StatusCode
	}

	for _, bad := range []string{
		`{"public":{"url":"home.example/mail"}}`,
		`{"public":{"url":"ftp://home.example"}}`,
		`{"public":{"url":"https://user@home.example"}}`,
		`{"public":{"url":"https://home.example/?x=1"}}`,
		`{"public":{"host":"mail.example.com:993"}}`,
		`{"public":{"host":"mail example"}}`,
		`{"public":{"imap":70000}}`,
		`{"public":{"smtp":-1}}`,
		`{"public":{"imaps":993}}`, // no Dovecot here
	} {
		if code := save(bad); code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, code)
		}
	}
	if got := state(); !strings.Contains(got, `"host":"nas.lan"`) || !strings.Contains(got, `"publicURL":""`) {
		t.Fatalf("refused settings were put to use:\n%s", got)
	}

	// A mail server name and ports that differ from what the container
	// listens on: a TCP proxy in front, or ports published under other numbers.
	if code := save(`{"public":{"host":"Mail.Example.com","imap":1993,"smtp":1465}}`); code != http.StatusOK {
		t.Fatalf("public mail addresses: %d", code)
	}
	got := state()
	for _, want := range []string{`"host":"Mail.Example.com"`, `"imapPort":"1993"`, `"smtpPort":"1465"`, `"imapsPort":""`} {
		if !strings.Contains(got, want) {
			t.Errorf("state lacks %s:\n%s", want, got)
		}
	}
	if w.s.ports.Settings() != (PortSettings{}) {
		t.Fatalf("a public port made the container listen: %+v", w.s.ports.Settings())
	}
	res := w.do("GET", "/api/users/u1/profile", "")
	body, _ := io.ReadAll(res.Body)
	if p := plistStrings(t, body); p["IncomingMailServerHostName"][0] != "Mail.Example.com" || p["OutgoingMailServerHostName"][0] != "Mail.Example.com" ||
		p["IncomingMailServerPortNumber"][0] != "1993" || p["OutgoingMailServerPortNumber"][0] != "1465" {
		t.Fatalf("profile: %v", p)
	}

	// A port to listen on is one thing, the port clients use another.
	port := freePort(t)
	if code := save(fmt.Sprintf(`{"ports":{"smtp":%d},"public":{"imap":1993}}`, port)); code != http.StatusOK {
		t.Fatalf("a port to listen on: %d", code)
	}
	if got := state(); !strings.Contains(got, `"imapPort":"1993"`) || !strings.Contains(got, fmt.Sprintf(`"smtpPort":"%d"`, port)) ||
		!strings.Contains(got, `"host":"nas.lan"`) || greeting(port) != "smtp" {
		t.Fatalf("after setting a port to listen on:\n%s", got)
	}

	// The public address of the page, with a sub-path of the reverse proxy.
	const mine, proxied = "http://example.com", "https://home.example"
	if res := w.do("GET", "/mb/", ""); res.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /mb/ before it is set: %d", res.StatusCode)
	}
	if code := save(`{"public":{"url":"https://home.example/mb/"}}`, "Origin", mine); code != http.StatusOK {
		t.Fatalf("setting the public address at the container's own address: %d", code)
	}
	if got := state(); !strings.Contains(got, `"publicURL":"https://home.example/mb"`) || !strings.Contains(got, `"host":"nas.lan"`) {
		t.Fatalf("state after setting the public address:\n%s", got)
	}
	for _, target := range []string{"/mb/", "/mb/app.js", "/", "/api/state", "/mb/api/state"} {
		if res := w.do("GET", target, ""); res.StatusCode != http.StatusOK {
			t.Errorf("GET %s: %d", target, res.StatusCode)
		}
	}
	// A proxy that passes the path on only finds the page under that path:
	// from behind it, the path cannot be changed or dropped.
	for _, body := range []string{`{"public":{"url":"https://home.example/other"}}`, `{"public":{"url":"https://home.example"}}`, `{}`} {
		if res := w.do("POST", "/mb/api/addresses", body); res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s from under /mb: %d", body, res.StatusCode)
		}
	}
	if res := w.do("POST", "/mb/api/addresses", `{"public":{"url":"https://other.example/mb","imap":1993}}`); res.StatusCode != http.StatusOK {
		t.Fatalf("another name with the same path, from under /mb: %d", res.StatusCode)
	}

	// It is still there after a restart, and can be changed from the proxy.
	w.s.public = NewPublic(w.s.cfg)
	if u := w.s.public.URL(); u == nil || u.String() != "https://other.example/mb" {
		t.Fatalf("public address after a restart: %v", u)
	}
	if code := save(`{"public":{"url":"https://home.example/"}}`, "Origin", proxied); code != http.StatusOK {
		t.Fatalf("changing the public address through the proxy: %d", code)
	}
	if res := w.do("GET", "/mb/", ""); res.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /mb/ after the path was dropped: %d", res.StatusCode)
	}
	// Without a server name of its own, mail goes to the name of the proxy.
	w.s.cfg.Hostname = ""
	if got := state(); !strings.Contains(got, `"host":"home.example"`) {
		t.Fatalf("mail host from the public address:\n%s", got)
	}
	if code := save(`{}`, "Origin", proxied); code != http.StatusOK {
		t.Fatalf("clearing everything: %d", code)
	}
	if got := state(); !strings.Contains(got, `"publicURL":""`) || !strings.Contains(got, `"host":"example.com"`) || !strings.Contains(got, `"smtpPort":"587"`) {
		t.Fatalf("state after clearing:\n%s", got)
	}
}

func TestCookiePath(t *testing.T) {
	for sent, want := range map[string]string{
		"1": "/", "": "/", "/": "/", "/mailbridge/": "/mailbridge/", "/a/b/": "/a/b/",
		"/no-slash": "/", "relative/": "/", "/a;b/": "/", "/a b/": "/", "/" + strings.Repeat("x", 300) + "/": "/",
	} {
		r := httptest.NewRequest("POST", "/api/session", nil)
		r.Header.Set(csrfHeader, sent)
		if got := cookiePath(r); got != want {
			t.Errorf("cookiePath(%q) = %q, want %q", sent, got, want)
		}
	}
}

func TestWebWithoutPublicURL(t *testing.T) {
	w := newWebTest(t, Config{TLSMode: "on"})
	if res := w.signIn("/api/session", "Origin", "https://whatever.example"); res.StatusCode != http.StatusOK || w.cookie == nil {
		t.Fatalf("sign-in: %d", res.StatusCode)
	}
	if !w.cookie.Secure || w.cookie.Path != "/" {
		t.Fatalf("session cookie: %+v", w.cookie)
	}
	if res := w.do("GET", "/mailbridge/", ""); res.StatusCode != http.StatusNotFound {
		t.Fatalf("a sub-path nobody configured: %d", res.StatusCode)
	}
}

func TestWebProfileAndPorts(t *testing.T) {
	w := newWebTest(t, Config{TLSMode: "on", Hostname: "nas.lan", IMAPPort: "143", SMTPPort: "587"})
	b := w.s.bridge
	b.status = "running"
	b.users = []User{
		{ID: "u1", Username: "jane@example.com", State: "connected", Password: "bridgepass", Addresses: []string{"jane@example.com", "alias@example.com"}},
		{ID: "u2", Username: "joe@example.com", State: "connected", SplitMode: true, Password: "other", Addresses: []string{"joe@example.com", "joe2@example.com"}},
		{ID: "u3", Username: "gone@example.com", State: "signedOut", Password: "x", Addresses: []string{"gone@example.com"}},
	}

	if res := w.do("GET", "/api/users/u1/profile", ""); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("profile without signing in: %d", res.StatusCode)
	}
	w.signIn("/api/session")

	res := w.do("GET", "/api/users/u1/profile", "")
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "application/x-apple-aspen-config" ||
		!strings.Contains(res.Header.Get("Content-Disposition"), "jane-example.com.mobileconfig") {
		t.Fatalf("profile: %d %v", res.StatusCode, res.Header)
	}
	got := plistStrings(t, body)
	if strings.Join(got["EmailAddress"], "|") != "jane@example.com" || got["IncomingPassword"][0] != "bridgepass" ||
		got["IncomingMailServerHostName"][0] != "nas.lan" || got["IncomingMailServerPortNumber"][0] != "143" || got["OutgoingMailServerPortNumber"][0] != "587" {
		t.Fatalf("profile content: %v", got)
	}

	// Split mode: one account per address.
	res = w.do("GET", "/api/users/u2/profile", "")
	body, _ = io.ReadAll(res.Body)
	if got := plistStrings(t, body); strings.Join(got["EmailAddress"], "|") != "joe@example.com|joe2@example.com" {
		t.Fatalf("split mode profile: %v", got["EmailAddress"])
	}
	for _, id := range []string{"u3", "nobody"} {
		if res := w.do("GET", "/api/users/"+id+"/profile", ""); res.StatusCode != http.StatusNotFound {
			t.Errorf("profile for %s: %d", id, res.StatusCode)
		}
	}

	// A port set in the web UI is the one shown and the one in the profile.
	port := freePort(t)
	if res := w.do("POST", "/api/addresses", fmt.Sprintf(`{"ports":{"imap":%d}}`, port)); res.StatusCode != http.StatusOK {
		t.Fatalf("setting a port: %d", res.StatusCode)
	}
	if greeting(port) != "imap" {
		t.Fatal("the port set in the web UI is not open")
	}
	res = w.do("GET", "/api/users/u1/profile", "")
	body, _ = io.ReadAll(res.Body)
	if got := plistStrings(t, body); got["IncomingMailServerPortNumber"][0] != fmt.Sprint(port) {
		t.Fatalf("profile after the port change: %v", got["IncomingMailServerPortNumber"])
	}
	if res := w.do("POST", "/api/addresses", `{"ports":{"imaps":993}}`); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("IMAPS without Dovecot: %d", res.StatusCode)
	}

	res = w.do("GET", "/api/state", "")
	body, _ = io.ReadAll(res.Body)
	for _, want := range []string{fmt.Sprintf(`"imapPort":"%d"`, port), `"host":"nas.lan"`, `"acmeLocked":""`, `"mailCertificate":false`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("state lacks %s:\n%s", want, body)
		}
	}
}

// A new container has no password: the first visitor chooses it, once.
func TestFirstVisitChoosesPassword(t *testing.T) {
	w := newWebTest(t, Config{TLSMode: "off"})
	dir := t.TempDir()
	auth, err := NewAuth(Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	w.s.auth = auth
	w.handler = w.s.routes()

	body := func(res *http.Response) string {
		data, _ := io.ReadAll(res.Body)
		return strings.TrimSpace(string(data))
	}
	if _, err := os.Stat(filepath.Join(dir, "webui.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a password file before anybody chose a password: %v", err)
	}

	// Nothing is served but the news that a password is wanted.
	for _, target := range []string{"/api/state", "/api/logs", "/api/acme"} {
		if res := w.do("GET", target, ""); res.StatusCode != http.StatusUnauthorized || !strings.Contains(body(res), `"setup":true`) {
			t.Fatalf("GET %s without a password: %s", target, res.Status)
		}
	}
	if res := w.do("POST", "/api/session", `{"password":""}`); res.StatusCode != http.StatusUnauthorized || !strings.Contains(body(res), `"setup":true`) {
		t.Fatalf("signing in with no password: %s", res.Status)
	}
	if res := w.do("POST", "/api/session", `{"password":"correct horse battery"}`); res.StatusCode != http.StatusUnauthorized || len(res.Cookies()) != 0 {
		t.Fatalf("signing in before a password exists: %s", res.Status)
	}

	// A password that is too short, and one without the header a page sends.
	if res := w.do("POST", "/api/setup", `{"password":"short"}`); res.StatusCode != http.StatusBadRequest || !strings.Contains(body(res), "10 characters") {
		t.Fatalf("a short password: %s", res.Status)
	}
	req := httptest.NewRequest("POST", "/api/setup", strings.NewReader(`{"password":"from another site 1"}`))
	rec := httptest.NewRecorder()
	w.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !auth.NeedsSetup() {
		t.Fatalf("a request from another site chose the password: %d", rec.Code)
	}

	res := w.do("POST", "/api/setup", `{"password":"my own password"}`, csrfHeader, "/")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("choosing a password: %s %s", res.Status, body(res))
	}
	for _, c := range res.Cookies() {
		if c.Name == sessionCookie {
			w.cookie = c
		}
	}
	if w.cookie == nil || !w.cookie.HttpOnly {
		t.Fatalf("no session after choosing a password: %v", res.Cookies())
	}
	if res := w.do("GET", "/api/state", ""); res.StatusCode != http.StatusOK {
		t.Fatalf("the page after choosing a password: %s", res.Status)
	}
	if fi, err := os.Stat(filepath.Join(dir, "webui.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the password file: %v, %v", fi, err)
	}

	// It cannot be chosen again, with or without a session.
	if res := w.do("POST", "/api/setup", `{"password":"somebody else's"}`); res.StatusCode != http.StatusConflict {
		t.Fatalf("choosing a password twice: %s", res.Status)
	}
	w.cookie = nil
	if res := w.do("POST", "/api/setup", `{"password":"somebody else's"}`); res.StatusCode != http.StatusConflict {
		t.Fatalf("choosing a password twice: %s", res.Status)
	}
	if res := w.do("GET", "/api/state", ""); res.StatusCode != http.StatusUnauthorized || strings.Contains(body(res), "setup") {
		t.Fatalf("signed out after the password was chosen: %s", res.Status)
	}
	if res := w.do("POST", "/api/session", `{"password":"my own password"}`); res.StatusCode != http.StatusOK {
		t.Fatalf("signing in with the chosen password: %s", res.Status)
	}

	// It is kept across a restart, and a password from the environment leaves nothing to choose.
	again, err := NewAuth(Config{DataDir: dir})
	if err != nil || again.NeedsSetup() {
		t.Fatalf("after a restart: needs setup %v, %v", again.NeedsSetup(), err)
	}
	if _, err := again.Login("my own password"); err != nil {
		t.Fatalf("signing in after a restart: %v", err)
	}
	fixed, err := NewAuth(Config{DataDir: t.TempDir(), Password: "from the environment"})
	if err != nil || fixed.NeedsSetup() {
		t.Fatalf("with MAILBRIDGE_PASSWORD: needs setup %v, %v", fixed.NeedsSetup(), err)
	}
	if _, err := fixed.Setup("my own password"); !errors.Is(err, ErrPasswordSet) {
		t.Fatalf("choosing a password over the one from the environment: %v", err)
	}
}
