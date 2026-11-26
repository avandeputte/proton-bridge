package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

// PublicSettings say where browsers and mail clients find this container
// when that is not where it listens: behind a reverse proxy for the web UI,
// a TCP proxy for IMAP and SMTP, or a port published under another number.
// They are set in the web UI. Empty and zero leave a value to the
// environment, or to what mailbridge works out by itself.
type PublicSettings struct {
	URL  string `json:"url"`  // of the web UI
	Host string `json:"host"` // server name for mail clients
	PortSettings
}

// Public holds the addresses shown to the user and written into profiles.
// Nothing here opens or closes a port.
type Public struct {
	cfg  Config
	path string

	mu       sync.Mutex
	settings PublicSettings
	url      *url.URL // settings.URL, parsed
}

// parsePublicURL reads the address of the web UI behind a reverse proxy.
func parsePublicURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("the public address of this page must look like https://mail.example.com or https://example.com/mailbridge, got %q", raw)
	}
	u.Path = path.Clean("/" + u.Path)
	u.RawPath = ""
	return u, nil
}

// validHost says whether s can be the server name given to mail clients: a
// host name, with or without dots, or an IP address.
func validHost(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// check tidies settings up and says what is wrong with them.
func (s *PublicSettings) check() (*url.URL, error) {
	s.URL = strings.TrimSpace(s.URL)
	s.Host = strings.TrimSpace(s.Host)

	var u *url.URL
	if s.URL != "" {
		var err error
		if u, err = parsePublicURL(s.URL); err != nil {
			return nil, err
		}
		s.URL = u.String()
	}
	if s.Host != "" && !validHost(s.Host) {
		return nil, fmt.Errorf("%q is not a server name. Enter a name such as mail.example.com, without a port", s.Host)
	}
	for _, port := range []int{s.IMAP, s.IMAPS, s.SMTP} {
		if port < 0 || port > 65535 {
			return nil, fmt.Errorf("%d is not a port number", port)
		}
	}
	return u, nil
}

func NewPublic(cfg Config) *Public {
	p := &Public{cfg: cfg, path: filepath.Join(cfg.DataDir, "public.json")}

	var stored PublicSettings
	data, err := os.ReadFile(p.path)
	if err == nil {
		if err = json.Unmarshal(data, &stored); err == nil {
			p.url, err = stored.check()
		}
	}
	switch {
	case err == nil:
		p.settings = stored
	case !errors.Is(err, os.ErrNotExist):
		log.Printf("cannot use the public addresses in %s, carrying on without: %v", p.path, err)
	}
	return p
}

// Settings are the values set in the web UI.
func (p *Public) Settings() PublicSettings {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.settings
}

// Set stores new values from the web UI.
func (p *Public) Set(s PublicSettings) error {
	u, err := s.check()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if err := os.WriteFile(p.path+".tmp", data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(p.path+".tmp", p.path); err != nil {
		return err
	}
	p.settings, p.url = s, u
	return nil
}

// URL is where browsers find the web UI when they do not reach it directly,
// or nil if nobody said.
func (p *Public) URL() *url.URL {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.url != nil {
		return p.url
	}
	return p.cfg.PublicURL
}

// BasePath is the path of the web UI in URL, without a slash at the end:
// empty unless it lives under a sub-path of a reverse proxy.
func (p *Public) BasePath() string {
	if u := p.URL(); u != nil {
		return strings.TrimRight(u.Path, "/")
	}
	return ""
}

// Port is the port mail clients are to use for a service, or zero if
// it is the one the container listens on.
func (p *Public) Port(service string) int {
	return p.Settings().of(service)
}
