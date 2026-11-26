package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// A mailProxy answers mail clients with the certificate from the CertStore and
// passes the session on to bridge.
//
// Bridge only ever presents its own self-signed certificate and cannot be
// given another one. So when there is a certificate that mail clients trust (a
// Let's Encrypt one, or the user's own), the plain byte-for-byte forwarder is
// replaced by this: TLS with the client ends here, a second TLS session runs
// from here to bridge on loopback, and the decrypted bytes are copied between
// the two.
//
// The LAN side works the way bridge is set to work: STARTTLS by default,
// TLS from the first byte when the protocol is switched to SSL/TLS in the web
// UI. For STARTTLS the proxy has to follow the conversation up to that
// command, which is the only protocol knowledge in here.
type mailProxy struct {
	name     string // for the log: "IMAP" or "SMTP"
	proto    string // "imap" or "smtp"
	certs    *CertStore
	upstream func() (addr string, implicitTLS bool)
	// pinned returns bridge's certificate (PEM). The upstream session is
	// only accepted with exactly that certificate.
	pinned func() ([]byte, error)

	mu        sync.Mutex
	pinnedDER []byte
}

const (
	mailHandshakeTimeout = 30 * time.Second
	mailPreTLSTimeout    = 2 * time.Minute
	mailMaxLine          = 8192
)

func startMailProxy(ctx context.Context, wg *sync.WaitGroup, p *mailProxy, addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("cannot listen for %s on %s: %v", p.name, addr, err)
	}
	target, _ := p.upstream()
	log.Printf("serving %s on %s with the certificate in use, passing sessions on to bridge at %s", p.name, ln.Addr(), target)

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		_ = ln.Close()
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("%s accept failed: %v", p.name, err)
				time.Sleep(200 * time.Millisecond)
				continue
			}
			go p.handle(ctx, conn)
		}
	}()
}

// upstreamTLS is the client configuration for the session with bridge.
func (p *mailProxy) upstreamTLS() (*tls.Config, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.pinnedDER == nil {
		data, err := p.pinned()
		if err != nil {
			return nil, fmt.Errorf("cannot read bridge's certificate: %w", err)
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("bridge's certificate is not PEM")
		}
		p.pinnedDER = block.Bytes
	}
	want := p.pinnedDER

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Bridge's certificate is self-signed and issued for 127.0.0.1: it
		// is checked by identity instead of by name and chain.
		InsecureSkipVerify: true, //nolint:gosec
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 || !bytes.Equal(raw[0], want) {
				return errors.New("bridge presented a different certificate than it exported")
			}
			return nil
		},
	}, nil
}

// forgetPinned makes the next session read bridge's certificate again, in
// case bridge made itself a new one.
func (p *mailProxy) forgetPinned() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pinnedDER = nil
}

func (p *mailProxy) handle(ctx context.Context, client net.Conn) {
	defer func() { _ = client.Close() }()

	addr, implicit := p.upstream()
	dialer := net.Dialer{Timeout: 5 * time.Second}
	up, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		log.Printf("%s: connection from %s refused, nothing is listening on %s (bridge only does once an account is signed in): %v",
			p.name, client.RemoteAddr(), addr, err)
		// Tell the mail client why, where the protocol has a way to.
		_ = client.SetWriteDeadline(time.Now().Add(5 * time.Second))
		switch {
		case implicit:
		case p.proto == "smtp":
			_, _ = io.WriteString(client, "421 4.3.2 Not ready: no Proton account is signed in\r\n")
		default:
			_, _ = io.WriteString(client, "* BYE Not ready: no Proton account is signed in\r\n")
		}
		return
	}
	defer func() { _ = up.Close() }()

	stop := context.AfterFunc(ctx, func() {
		_ = client.Close()
		_ = up.Close()
	})
	defer stop()

	var tlsClient, tlsUp *tls.Conn
	if implicit {
		tlsClient, tlsUp, err = p.secure(client, up)
	} else {
		_ = client.SetDeadline(time.Now().Add(mailPreTLSTimeout))
		_ = up.SetDeadline(time.Now().Add(mailPreTLSTimeout))
		switch p.proto {
		case "smtp":
			tlsClient, tlsUp, err = p.smtpUntilTLS(client, up)
		default:
			tlsClient, tlsUp, err = p.imapUntilTLS(client, up)
		}
	}
	if err != nil {
		if !errors.Is(err, io.EOF) && ctx.Err() == nil {
			log.Printf("%s: session from %s ended before encryption started: %v", p.name, client.RemoteAddr(), err)
		}
		return
	}
	if tlsClient == nil {
		return // the client left politely before STARTTLS
	}
	_ = client.SetDeadline(time.Time{})
	_ = up.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	pipe := func(dst, src *tls.Conn) {
		_, _ = io.Copy(dst, src)
		_ = dst.CloseWrite()
		done <- struct{}{}
	}
	go pipe(tlsUp, tlsClient)
	go pipe(tlsClient, tlsUp)

	<-done
	// Give the other direction a moment to flush, then tear everything down.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// secure starts TLS on both connections: first with bridge, so that a client
// is never told to go ahead when bridge cannot follow.
func (p *mailProxy) secure(client, up net.Conn) (*tls.Conn, *tls.Conn, error) {
	cfg, err := p.upstreamTLS()
	if err != nil {
		return nil, nil, err
	}
	deadline := time.Now().Add(mailHandshakeTimeout)
	_ = up.SetDeadline(deadline)
	_ = client.SetDeadline(deadline)

	tlsUp := tls.Client(up, cfg)
	if err := tlsUp.Handshake(); err != nil {
		p.forgetPinned()
		return nil, nil, fmt.Errorf("TLS with bridge: %w", err)
	}
	tlsClient := tls.Server(client, p.certs.TLSConfig())
	if err := tlsClient.Handshake(); err != nil {
		return nil, nil, fmt.Errorf("TLS with the mail client: %w", err)
	}
	return tlsClient, tlsUp, nil
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", errors.New("line too long")
	}
	if err != nil {
		return "", err
	}
	return string(line), nil
}

// smtpReply reads one, possibly multi-line, SMTP reply.
func smtpReply(r *bufio.Reader) (code string, text string, err error) {
	var sb strings.Builder
	for {
		line, err := readLine(r)
		if err != nil {
			return "", "", err
		}
		sb.WriteString(line)
		if len(line) < 4 {
			return "", "", fmt.Errorf("malformed SMTP reply %q", line)
		}
		if line[3] != '-' {
			return line[:3], sb.String(), nil
		}
	}
}

// smtpUntilTLS relays the start of an SMTP session up to STARTTLS.
func (p *mailProxy) smtpUntilTLS(client, up net.Conn) (*tls.Conn, *tls.Conn, error) {
	cr, ur := bufio.NewReaderSize(client, mailMaxLine), bufio.NewReaderSize(up, mailMaxLine)

	// relay passes one reply from bridge to the client.
	relay := func() (string, error) {
		code, text, err := smtpReply(ur)
		if err != nil {
			return "", err
		}
		_, err = io.WriteString(client, text)
		return code, err
	}

	if _, err := relay(); err != nil { // greeting
		return nil, nil, err
	}
	for {
		line, err := readLine(cr)
		if err != nil {
			return nil, nil, err
		}
		verb := strings.ToUpper(strings.TrimSpace(line))
		if i := strings.IndexByte(verb, ' '); i >= 0 {
			verb = verb[:i]
		}

		switch verb {
		case "EHLO", "HELO", "NOOP", "RSET", "QUIT":
			if _, err := io.WriteString(up, line); err != nil {
				return nil, nil, err
			}
			if _, err := relay(); err != nil {
				return nil, nil, err
			}
			if verb == "QUIT" {
				return nil, nil, nil
			}

		case "STARTTLS":
			// Anything sent along with the command would otherwise be read
			// as if it had arrived encrypted.
			if cr.Buffered() > 0 {
				return nil, nil, errors.New("data after STARTTLS")
			}
			if _, err := io.WriteString(up, "STARTTLS\r\n"); err != nil {
				return nil, nil, err
			}
			code, text, err := smtpReply(ur)
			if err != nil {
				return nil, nil, err
			}
			if code != "220" || ur.Buffered() > 0 {
				_, _ = io.WriteString(client, "454 4.7.0 TLS is not available right now\r\n")
				return nil, nil, fmt.Errorf("bridge refused STARTTLS: %s", strings.TrimSpace(text))
			}
			return p.startTLS(client, up, "220 2.0.0 Ready to start TLS\r\n", "454 4.7.0 TLS is not available right now\r\n")

		default:
			if _, err := io.WriteString(client, "530 5.7.0 Must issue a STARTTLS command first\r\n"); err != nil {
				return nil, nil, err
			}
		}
	}
}

// imapUntilTLS relays the start of an IMAP session up to STARTTLS.
func (p *mailProxy) imapUntilTLS(client, up net.Conn) (*tls.Conn, *tls.Conn, error) {
	cr, ur := bufio.NewReaderSize(client, mailMaxLine), bufio.NewReaderSize(up, mailMaxLine)

	// relay passes bridge's responses to the client up to the one that
	// completes the command, and reports whether that one says OK.
	relay := func(tag string, toClient bool) (bool, error) {
		for {
			line, err := readLine(ur)
			if err != nil {
				return false, err
			}
			rest, tagged := strings.CutPrefix(line, tag+" ")
			if toClient || !tagged {
				if _, err := io.WriteString(client, line); err != nil {
					return false, err
				}
			}
			if tagged {
				return strings.HasPrefix(strings.ToUpper(rest), "OK"), nil
			}
		}
	}

	greeting, err := readLine(ur)
	if err != nil {
		return nil, nil, err
	}
	if _, err := io.WriteString(client, greeting); err != nil {
		return nil, nil, err
	}

	for {
		line, err := readLine(cr)
		if err != nil {
			return nil, nil, err
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			if _, err := io.WriteString(client, "* BAD Invalid command\r\n"); err != nil {
				return nil, nil, err
			}
			continue
		}
		tag, verb := fields[0], strings.ToUpper(fields[1])

		switch {
		case strings.HasSuffix(strings.TrimSpace(line), "}"):
			// A literal follows, which this proxy does not relay before TLS.
			_, _ = fmt.Fprintf(client, "%s BAD Use STARTTLS first\r\n", tag)
			return nil, nil, errors.New("literal before STARTTLS")

		case verb == "CAPABILITY" || verb == "NOOP" || verb == "ID" || verb == "LOGOUT":
			if _, err := io.WriteString(up, line); err != nil {
				return nil, nil, err
			}
			if _, err := relay(tag, true); err != nil {
				return nil, nil, err
			}
			if verb == "LOGOUT" {
				return nil, nil, nil
			}

		case verb == "STARTTLS":
			if cr.Buffered() > 0 {
				return nil, nil, errors.New("data after STARTTLS")
			}
			if _, err := fmt.Fprintf(up, "%s STARTTLS\r\n", tag); err != nil {
				return nil, nil, err
			}
			ok, err := relay(tag, false)
			if err != nil {
				return nil, nil, err
			}
			if !ok || ur.Buffered() > 0 {
				_, _ = fmt.Fprintf(client, "%s NO TLS is not available right now\r\n", tag)
				return nil, nil, errors.New("bridge refused STARTTLS")
			}
			return p.startTLS(client, up, tag+" OK Begin TLS negotiation now\r\n", tag+" NO TLS is not available right now\r\n")

		default:
			// Signing in without encryption would send the bridge password
			// across the LAN in the clear.
			if _, err := fmt.Fprintf(client, "%s NO [PRIVACYREQUIRED] Use STARTTLS first\r\n", tag); err != nil {
				return nil, nil, err
			}
		}
	}
}

// startTLS is the second half of STARTTLS: bridge has agreed already. TLS with
// bridge comes first, so that the client is only told to go ahead when the
// whole path is ready.
func (p *mailProxy) startTLS(client, up net.Conn, goAhead, sorry string) (*tls.Conn, *tls.Conn, error) {
	cfg, err := p.upstreamTLS()
	if err != nil {
		_, _ = io.WriteString(client, sorry)
		return nil, nil, err
	}
	deadline := time.Now().Add(mailHandshakeTimeout)
	_ = up.SetDeadline(deadline)
	_ = client.SetDeadline(deadline)

	tlsUp := tls.Client(up, cfg)
	if err := tlsUp.Handshake(); err != nil {
		p.forgetPinned()
		_, _ = io.WriteString(client, sorry)
		return nil, nil, fmt.Errorf("TLS with bridge: %w", err)
	}
	if _, err := io.WriteString(client, goAhead); err != nil {
		return nil, nil, err
	}
	tlsClient := tls.Server(client, p.certs.TLSConfig())
	if err := tlsClient.Handshake(); err != nil {
		return nil, nil, fmt.Errorf("TLS with the mail client: %w", err)
	}
	return tlsClient, tlsUp, nil
}
