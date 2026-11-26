package main

import (
	"net"
	"regexp"
	"strings"
)

// Mail clients are terse about why they will not connect, and installers of
// configuration profiles say even less. What the server side sees of a
// failure is shown in the web UI, where the person setting things up looks.

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
