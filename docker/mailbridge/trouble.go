package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Mail clients are terse about why they will not connect, and installers of
// configuration profiles say even less. What the server side sees of a
// failure is shown in the web UI, where the person setting things up looks.
// The same goes for a browser that will not open the web UI itself.

// troubleRepeat is how long the same trouble from the same client is kept
// to itself after it was reported. A browser window that cannot connect
// tries again every few seconds for as long as it stays open.
const troubleRepeat = 15 * time.Minute

// certTurnedDown says whether the text of a failed TLS handshake means that
// the client did not accept the server's certificate, and in which words.
// It knows how Go and OpenSSL (Dovecot) put the alerts a client can send.
func certTurnedDown(msg string) (how string, ok bool) {
	msg = strings.ToLower(msg)
	for _, alert := range []struct{ text, how string }{
		{"unknown certificate authority", "it does not know who issued it"},
		{"unknown ca", "it does not know who issued it"},
		{"bad certificate", "it found the certificate invalid"},
		{"unknown certificate", "it does not trust it"},
		{"certificate unknown", "it does not trust it"},
		{"expired certificate", "it found the certificate expired"},
		{"certificate expired", "it found the certificate expired"},
	} {
		if strings.Contains(msg, alert.text) {
			return alert.how, true
		}
	}
	return "", false
}

// remoteHost is the address of a client without the port.
func remoteHost(addr net.Addr) string {
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}

// mailTrouble turns failures of mail clients into notices in the web UI.
type mailTrouble struct {
	certs  *CertStore
	notify func(level, format string, args ...any)
}

// certificate reports a client that turned the certificate down.
func (t *mailTrouble) certificate(service, remote, how string) {
	info := t.certs.Info()
	advice := "It is good for " + strings.Join(info.Names, ", ") + ": check that the client connects by one of these names."
	if !t.certs.Trusted() {
		advice = "The certificate is self-signed, which a mail client accepts only when you tell it to. Software that cannot ask, " +
			"such as the installer of a profile on a Mac, gives up instead. A certificate from Let's Encrypt (see the Certificate card) avoids both."
	}
	t.notify("warn", "A mail client at %s did not accept this server's certificate for %s: %s. %s", remote, service, how, advice)
}

var (
	dovecotRemote = regexp.MustCompile(`\brip=([0-9A-Fa-f:.]+)`)
	dovecotUser   = regexp.MustCompile(`\buser=<([^>]*)>`)
)

// dovecotLine looks at a line of Dovecot's log for a client in trouble.
func (t *mailTrouble) dovecotLine(line string) {
	if !strings.Contains(line, "-login: ") {
		return
	}
	remote := "an unknown address"
	if m := dovecotRemote.FindStringSubmatch(line); m != nil {
		remote = m[1]
	}
	if strings.Contains(line, "auth failed") {
		user := "an unknown name"
		if m := dovecotUser.FindStringSubmatch(line); m != nil && m[1] != "" {
			user = m[1]
		}
		t.notify("warn", "A mail client at %s tried to sign in to IMAP as %s and was refused. "+
			"The username is the Proton address and the password is the bridge password from the account card, not the Proton password.", remote, user)
		return
	}
	if how, ok := certTurnedDown(line); ok {
		t.certificate("IMAP", remote, how)
	}
}

// quiet lets a report that keeps coming through once per period.
type quiet struct {
	period time.Duration

	mu   sync.Mutex
	seen map[string]*repeat
}

type repeat struct {
	reported time.Time
	held     int
}

// again says whether to report key now, and how many times it was held back
// since it was last reported.
func (q *quiet) again(key string) (held int, ok bool) {
	now := time.Now()
	q.mu.Lock()
	defer q.mu.Unlock()

	r := q.seen[key]
	if r != nil && now.Sub(r.reported) < q.period {
		r.held++
		return 0, false
	}
	if r == nil {
		if len(q.seen) >= 256 {
			// Whoever fills this is not somebody to keep a count for.
			q.seen = nil
		}
		if q.seen == nil {
			q.seen = map[string]*repeat{}
		}
		r = &repeat{}
		q.seen[key] = r
	}
	held = r.held
	r.reported, r.held = now, 0
	return held, true
}

// askedFor remembers which server name each new TLS connection asked for.
// When a handshake fails, net/http only tells the client's address.
type askedFor struct {
	mu    sync.Mutex
	names map[string]asked // by the client's address and port
}

type asked struct {
	name string
	at   time.Time
}

func (a *askedFor) note(remote, name string) {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.names == nil {
		a.names = map[string]asked{}
	}
	// Handshakes that went well are never asked about.
	if len(a.names) >= 64 {
		for remote, entry := range a.names {
			if now.Sub(entry.at) > time.Minute {
				delete(a.names, remote)
			}
		}
	}
	if len(a.names) < 1024 {
		a.names[remote] = asked{name: name, at: now}
	}
}

func (a *askedFor) take(remote string) (name string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.names[remote]
	delete(a.names, remote)
	return entry.name, ok
}

// webTrouble explains connections to the web UI that end before a page is
// served. net/http writes a line for each, which says little and comes every
// few seconds from a browser window that keeps trying.
type webTrouble struct {
	certs  *CertStore
	public func() *url.URL // where the page is to be opened, or nil
	notify func(level, format string, args ...any)

	asked askedFor
	quiet quiet
}

func newWebTrouble(certs *CertStore, public func() *url.URL, notify func(level, format string, args ...any)) *webTrouble {
	return &webTrouble{certs: certs, public: public, notify: notify, quiet: quiet{period: troubleRepeat}}
}

// watch makes srv, which is about to serve HTTPS, report to t.
func (t *webTrouble) watch(srv *http.Server) {
	conf := t.certs.TLSConfig()
	conf.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		t.asked.note(hello.Conn.RemoteAddr().String(), hello.ServerName)
		return t.certs.GetCertificate(hello)
	}
	srv.TLSConfig = conf
	srv.ErrorLog = log.New(t, "", 0)
}

var handshakeError = regexp.MustCompile(`^http: TLS handshake error from (\S+): (.*)`)

// Write takes what net/http has to log, a line at a time.
func (t *webTrouble) Write(line []byte) (int, error) {
	text := strings.TrimRight(string(line), "\n")
	if m := handshakeError.FindStringSubmatch(text); m != nil {
		t.handshake(m[1], m[2])
	} else {
		log.Print(text)
	}
	return len(line), nil
}

// again is quiet.again with the words for the log about what was held back.
func (t *webTrouble) again(key string) (more string, ok bool) {
	held, ok := t.quiet.again(key)
	if held > 0 {
		more = " (" + strconv.Itoa(held) + " more since this was last reported)"
	}
	return more, ok
}

// handshake looks at a TLS handshake that failed with the client at addr.
func (t *webTrouble) handshake(addr, msg string) {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	name, known := t.asked.take(addr)

	if how, ok := certTurnedDown(msg); ok {
		t.certificate(host, name, known, how)
		return
	}
	if strings.Contains(msg, "HTTP request to an HTTPS server") {
		if more, ok := t.again("http " + host); ok {
			log.Printf("web UI: %s asked for this page with http://, and it is served with https:// only%s", host, more)
		}
		return
	}
	// The text holds the client's port: what went wrong is at its end.
	what := msg[strings.LastIndex(msg, ": ")+1:]
	if more, ok := t.again("other " + host + what); ok {
		log.Printf("web UI: a connection from %s ended before it was encrypted: %s%s", host, msg, more)
	}
}

// certificate reports a browser that turned the certificate down.
func (t *webTrouble) certificate(host, name string, known bool, how string) {
	more, ok := t.again("certificate " + host + " " + name)
	if !ok {
		return
	}
	if !t.certs.Trusted() {
		// What every browser does until the person in front of it says to go on.
		log.Printf("web UI: the browser at %s did not accept the self-signed certificate%s. "+
			"A browser asks about it once; a certificate from Let's Encrypt avoids the question.", host, more)
		return
	}
	if more != "" {
		log.Printf("web UI: the browser at %s still does not accept the certificate%s", host, more)
	}

	names := strings.Join(t.certs.Info().Names, ", ")
	instead := "Open the page by a name the certificate is good for."
	if u := t.public(); u != nil {
		instead = "Open the page as " + u.String() + " instead."
	}
	if known && name != "" && t.certs.Covers(name) {
		t.notify("warn", "A browser at %s opened this page as %s and did not accept the certificate, although it is good for %s: %s. "+
			"Its clock may be wrong, or it does not know the issuer, %s.", host, name, names, how, t.certs.Info().Issuer)
		return
	}
	by := ""
	switch {
	case known && name == "":
		by = " by IP address"
	case known:
		by = " as " + name
	}
	t.notify("warn", "A browser at %s opened this page%s and did not accept the certificate, which is good for %s. %s "+
		"A window left open at an old address keeps trying until it is closed.", host, by, names, instead)
}
