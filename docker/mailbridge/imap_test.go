package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// imapClient is just enough of an IMAP client to play the part of a mail
// client (or of Proton, on the far side) in the integration test.
type imapClient struct {
	t    *testing.T
	name string
	conn net.Conn
	r    *bufio.Reader
	tag  int
}

// dialIMAP connects, upgrades with STARTTLS when the server offers it, and logs in.
func dialIMAP(t *testing.T, name, addr, user, pass string) *imapClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	c := &imapClient{t: t, name: name, conn: conn, r: bufio.NewReader(conn)}
	t.Cleanup(func() { _ = c.conn.Close() })

	greeting := c.line()
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("%s: unexpected greeting %q", name, greeting)
	}
	caps := strings.Join(c.cmd("CAPABILITY"), " ")
	if strings.Contains(caps, "STARTTLS") {
		c.cmd("STARTTLS")
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- test against a throwaway local server
		if err := tc.Handshake(); err != nil {
			t.Fatalf("%s: TLS handshake: %v", name, err)
		}
		c.conn, c.r = tc, bufio.NewReader(tc)
	}
	c.cmd("LOGIN %s %s", quote(user), quote(pass))
	return c
}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func (c *imapClient) line() string {
	_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	line, err := c.r.ReadString('\n')
	if err != nil {
		c.t.Fatalf("%s: read: %v", c.name, err)
	}
	return strings.TrimRight(line, "\r\n")
}

// try sends one command and returns the untagged responses.
func (c *imapClient) try(format string, args ...any) ([]string, error) {
	c.tag++
	tag := "a" + strconv.Itoa(c.tag)
	command := fmt.Sprintf(format, args...)
	if _, err := fmt.Fprintf(c.conn, "%s %s\r\n", tag, command); err != nil {
		c.t.Fatalf("%s: write: %v", c.name, err)
	}
	var untagged []string
	for {
		line := c.line()
		if rest, ok := strings.CutPrefix(line, tag+" "); ok {
			if strings.HasPrefix(rest, "OK") {
				return untagged, nil
			}
			return untagged, fmt.Errorf("%s: %s: %s", c.name, strings.SplitN(command, " ", 2)[0], rest)
		}
		untagged = append(untagged, line)
	}
}

func (c *imapClient) cmd(format string, args ...any) []string {
	c.t.Helper()
	lines, err := c.try(format, args...)
	if err != nil {
		c.t.Fatal(err)
	}
	return lines
}

// add stores a message in a mailbox.
func (c *imapClient) add(box, message string) {
	c.t.Helper()
	message = strings.ReplaceAll(message, "\n", "\r\n")
	c.tag++
	tag := "a" + strconv.Itoa(c.tag)
	fmt.Fprintf(c.conn, "%s APPEND %s \"26-Nov-2026 10:00:00 +0000\" {%d}\r\n", tag, quote(box), len(message))
	if line := c.line(); !strings.HasPrefix(line, "+") {
		c.t.Fatalf("%s: APPEND to %s refused: %s", c.name, box, line)
	}
	fmt.Fprintf(c.conn, "%s\r\n", message)
	for {
		line := c.line()
		if rest, ok := strings.CutPrefix(line, tag+" "); ok {
			if !strings.HasPrefix(rest, "OK") {
				c.t.Fatalf("%s: APPEND to %s: %s", c.name, box, rest)
			}
			return
		}
	}
}

// count is the number of messages in a mailbox, or -1 if it does not exist.
func (c *imapClient) count(box string) int {
	lines, err := c.try("STATUS %s (MESSAGES)", quote(box))
	if err != nil {
		return -1
	}
	for _, line := range lines {
		if i := strings.LastIndex(line, "MESSAGES "); i >= 0 && strings.HasPrefix(line, "* STATUS") {
			n, _ := strconv.Atoi(strings.TrimRight(line[i+len("MESSAGES "):], ") "))
			return n
		}
	}
	return -1
}

// search selects a mailbox and returns the UIDs matching the criteria.
func (c *imapClient) search(box, criteria string) []string {
	c.t.Helper()
	c.cmd("SELECT %s", quote(box))
	for _, line := range c.cmd("UID SEARCH %s", criteria) {
		if rest, ok := strings.CutPrefix(line, "* SEARCH"); ok {
			return strings.Fields(rest)
		}
	}
	return nil
}

// mailboxes lists mailbox names with LIST or LSUB.
func (c *imapClient) mailboxes(command string) []string {
	c.t.Helper()
	var names []string
	for _, line := range c.cmd(`%s "" "*"`, command) {
		if !strings.HasPrefix(line, "* "+command) {
			continue
		}
		name := line[strings.LastIndex(line, `" `)+2:]
		if i := strings.Index(line, `) "/" `); i >= 0 {
			name = line[i+len(`) "/" `):]
		}
		names = append(names, strings.Trim(name, `"`))
	}
	return names
}

func message(n int, subject, body string) string {
	return fmt.Sprintf("From: Sender <sender@example.org>\nTo: Jane <jane@example.com>\nSubject: %s\n"+
		"Date: Thu, 26 Nov 2026 10:%02d:00 +0000\nMessage-ID: <test-%d-%d@example.org>\n"+
		"MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\n%s\n",
		subject, n%60, n, time.Now().UnixNano(), body)
}
