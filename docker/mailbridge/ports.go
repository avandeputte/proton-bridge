package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// The LAN-facing mail services.
const (
	svcIMAP  = "imap"
	svcIMAPS = "imaps"
	svcSMTP  = "smtp"
)

var svcNames = map[string]string{svcIMAP: "IMAP", svcIMAPS: "IMAPS", svcSMTP: "SMTP"}

// PortSettings are the port numbers chosen in the web UI. Zero leaves a
// service on the port from the environment.
type PortSettings struct {
	IMAP  int `json:"imap"`
	IMAPS int `json:"imaps"`
	SMTP  int `json:"smtp"`
}

func (s PortSettings) of(service string) int {
	switch service {
	case svcIMAP:
		return s.IMAP
	case svcIMAPS:
		return s.IMAPS
	default:
		return s.SMTP
	}
}

// Ports opens the ports mail clients connect to. The ones from the
// environment are opened at start-up and stay. On top of those, each service
// can be given a port in the web UI, which is opened and closed while running.
//
// A port from the web UI is opened in addition to the default one, not instead
// of it. That way it does not matter how the container is attached to the
// network: with host networking the new port is simply there, and with
// published ports either "2143:2143" or "2143:143" reaches the service.
type Ports struct {
	cfg  Config
	ctx  context.Context
	wg   *sync.WaitGroup
	path string

	mu       sync.Mutex
	handlers map[string]handler
	settings PortSettings
	open     map[string][]net.Listener // the ports from the web UI
}

func NewPorts(ctx context.Context, wg *sync.WaitGroup, cfg Config) *Ports {
	return &Ports{
		cfg:      cfg,
		ctx:      ctx,
		wg:       wg,
		path:     filepath.Join(cfg.DataDir, "ports.json"),
		handlers: map[string]handler{},
		open:     map[string][]net.Listener{},
	}
}

// Handle sets what serves the connections of a service.
func (p *Ports) Handle(service string, h handler) { p.handlers[service] = h }

// Offers says whether a service exists in this mode of operation.
func (p *Ports) Offers(service string) bool { return p.handlers[service] != nil }

func (p *Ports) fromEnv(service string) []string {
	switch service {
	case svcIMAP:
		return p.cfg.IMAPListen
	case svcIMAPS:
		return p.cfg.IMAPSListen
	default:
		return p.cfg.SMTPListen
	}
}

// listensOn says whether a port from the environment already serves the service.
func (p *Ports) listensOn(service string, port int) bool {
	for _, addr := range p.fromEnv(service) {
		if _, have, err := net.SplitHostPort(addr); err == nil && have == strconv.Itoa(port) {
			return true
		}
	}
	return false
}

// openPort opens a port from the web UI for a service, on the same
// interfaces as the service's ports from the environment.
func (p *Ports) openPort(service string, port int) ([]net.Listener, error) {
	hosts := []string{}
	for _, addr := range p.fromEnv(service) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		known := false
		for _, h := range hosts {
			known = known || h == host
		}
		if !known {
			hosts = append(hosts, host)
		}
	}
	if len(hosts) == 0 {
		hosts = []string{""}
	}

	var lns []net.Listener
	for _, host := range hosts {
		ln, err := listen(p.ctx, p.wg, svcNames[service], net.JoinHostPort(host, strconv.Itoa(port)), p.handlers[service])
		if err != nil {
			closeAll(lns)
			return nil, err
		}
		lns = append(lns, ln)
	}
	return lns, nil
}

func closeAll(lns []net.Listener) {
	for _, ln := range lns {
		_ = ln.Close()
	}
}

// Start opens the ports from the environment, which have to work, and then
// the ones chosen in the web UI. Problems with the latter are returned for
// the user to see, because they can be fixed in the web UI.
func (p *Ports) Start() []string {
	for service, handle := range p.handlers {
		name := svcNames[service]
		for _, addr := range p.fromEnv(service) {
			ln, err := listen(p.ctx, p.wg, name, addr, handle)
			if err != nil {
				log.Fatalf("cannot listen for %s on %s: %v", name, addr, err)
			}
			log.Printf("%s: listening on %s", name, ln.Addr())
		}
	}

	var stored PortSettings
	data, err := os.ReadFile(p.path)
	if err == nil {
		err = json.Unmarshal(data, &stored)
	}
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("cannot read the port settings in %s, carrying on without: %v", p.path, err)
		}
		return nil
	}

	var problems []string
	p.mu.Lock()
	defer p.mu.Unlock()
	p.settings = stored
	for _, service := range []string{svcIMAP, svcIMAPS, svcSMTP} {
		port := stored.of(service)
		if port == 0 || !p.Offers(service) || p.listensOn(service, port) {
			continue
		}
		lns, err := p.openPort(service, port)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s is set to port %d in the web UI, but that port cannot be opened: %v", svcNames[service], port, err))
			continue
		}
		p.open[service] = lns
		log.Printf("%s: also listening on port %d (set in the web UI)", svcNames[service], port)
	}
	return problems
}

// Settings are the port numbers chosen in the web UI.
func (p *Ports) Settings() PortSettings {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.settings
}

// Shown is the port number mail clients are told to use for a service, or
// empty if the service is not offered.
func (p *Ports) Shown(service string) string {
	if port := p.Settings().of(service); port != 0 && p.Offers(service) {
		return strconv.Itoa(port)
	}
	switch service {
	case svcIMAP:
		return p.cfg.IMAPPort
	case svcIMAPS:
		return p.cfg.IMAPSPort
	default:
		return p.cfg.SMTPPort
	}
}

// Set changes the port numbers chosen in the web UI. Nothing changes if one
// of the new ports cannot be opened.
func (p *Ports) Set(want PortSettings) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	services := []string{svcIMAP, svcIMAPS, svcSMTP}
	for _, service := range services {
		port := want.of(service)
		switch {
		case port == 0:
		case port < 1 || port > 65535:
			return fmt.Errorf("%d is not a port number", port)
		case !p.Offers(service):
			return errors.New("IMAP over SSL/TLS on a port of its own needs Dovecot mode. Without it, the IMAP port takes SSL/TLS as well as STARTTLS")
		}
	}

	opened := map[string][]net.Listener{}
	undo := func() {
		for _, lns := range opened {
			closeAll(lns)
		}
	}
	for _, service := range services {
		port := want.of(service)
		if port == p.settings.of(service) || port == 0 || p.listensOn(service, port) {
			continue
		}
		lns, err := p.openPort(service, port)
		if err != nil {
			undo()
			return fmt.Errorf("cannot open port %d for %s: %v", port, svcNames[service], err)
		}
		opened[service] = lns
	}

	data, err := json.MarshalIndent(want, "", "  ")
	if err == nil {
		if err = os.WriteFile(p.path+".tmp", data, 0o600); err == nil {
			err = os.Rename(p.path+".tmp", p.path)
		}
	}
	if err != nil {
		undo()
		return err
	}

	for _, service := range services {
		if want.of(service) == p.settings.of(service) {
			continue
		}
		// Sessions that are open carry on; only new ones are turned away.
		closeAll(p.open[service])
		delete(p.open, service)
		if lns := opened[service]; lns != nil {
			p.open[service] = lns
			log.Printf("%s: also listening on port %d (set in the web UI)", svcNames[service], want.of(service))
		}
	}
	p.settings = want
	return nil
}
