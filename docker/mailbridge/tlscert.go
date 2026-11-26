package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Where a certificate came from.
const (
	certSelfSigned  = "self-signed"
	certOwn         = "own"
	certLetsEncrypt = "letsencrypt"
)

// certWatchInterval is how often CertStore.Watch looks at the files. Tests shorten it.
var certWatchInterval = time.Minute

// CertInfo describes the certificate in use, for the web UI.
type CertInfo struct {
	Origin   string    `json:"origin"`
	Issuer   string    `json:"issuer"`
	Names    []string  `json:"names"`
	NotAfter time.Time `json:"notAfter"`
}

// CertStore holds the certificate that the web UI, Dovecot and the mail TLS
// proxy present, and lets it be replaced while everything keeps running.
//
// The certificate in use is also kept as a pair of files of its own, because
// Dovecot reads its certificate from disk.
type CertStore struct {
	certPath, keyPath string

	mu       sync.RWMutex
	cert     *tls.Certificate
	info     CertInfo
	onChange []func()
}

// NewCertStore starts with the certificate the user configured, or else with
// a self-signed one.
func NewCertStore(cfg Config) (*CertStore, error) {
	dir := filepath.Join(cfg.DataDir, "tls")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &CertStore{certPath: filepath.Join(dir, "cert.pem"), keyPath: filepath.Join(dir, "key.pem")}

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		if err := s.Load(cfg.TLSCert, cfg.TLSKey, certOwn); err != nil {
			return nil, fmt.Errorf("cannot use MAILBRIDGE_TLS_CERT and MAILBRIDGE_TLS_KEY: %w", err)
		}
		return s, nil
	}

	certPath, keyPath, err := ensureSelfSigned(cfg)
	if err != nil {
		return nil, err
	}
	return s, s.Load(certPath, keyPath, certSelfSigned)
}

// Load switches to the certificate and key in the given files. Nothing changes
// if they do not form a valid pair, or if the certificate has expired.
func (s *CertStore) Load(certPath, keyPath, origin string) error {
	certPEM, err := os.ReadFile(certPath) //nolint:gosec
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyPath) //nolint:gosec
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	cert.Leaf = leaf

	names := append([]string{}, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cert != nil && bytes.Equal(s.cert.Certificate[0], cert.Certificate[0]) {
		return nil // already in use
	}
	if time.Now().After(leaf.NotAfter) {
		// At start-up an expired certificate still beats no web page at all.
		if s.cert != nil {
			return fmt.Errorf("the certificate expired on %s", leaf.NotAfter.Format("2006-01-02"))
		}
		log.Printf("warning: the certificate in %s expired on %s", certPath, leaf.NotAfter.Format("2006-01-02"))
	}

	// Key first: whoever reads the two files while they are being replaced
	// gets a pair that does not match, never a certificate with a stale key
	// that happens to load.
	for _, f := range []struct {
		path string
		data []byte
	}{{s.keyPath, keyPEM}, {s.certPath, certPEM}} {
		if err := os.WriteFile(f.path+".tmp", f.data, 0o600); err != nil {
			return err
		}
		if err := os.Rename(f.path+".tmp", f.path); err != nil {
			return err
		}
	}

	replaced := s.cert != nil
	issuer := leaf.Issuer.CommonName
	if len(leaf.Issuer.Organization) > 0 {
		issuer = leaf.Issuer.Organization[0]
	}
	s.cert, s.info = &cert, CertInfo{Origin: origin, Issuer: issuer, Names: names, NotAfter: leaf.NotAfter}
	if replaced {
		log.Printf("now using the %s certificate for %v, valid until %s", origin, names, leaf.NotAfter.Format("2006-01-02"))
		for _, fn := range s.onChange {
			go fn()
		}
	}
	return nil
}

// Paths are the files holding the certificate in use and its key.
func (s *CertStore) Paths() (certPath, keyPath string) { return s.certPath, s.keyPath }

// GetCertificate is for tls.Config.
func (s *CertStore) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cert == nil {
		return nil, errors.New("no certificate")
	}
	return s.cert, nil
}

// TLSConfig is the server side configuration for everything that presents the certificate.
func (s *CertStore) TLSConfig() *tls.Config {
	return &tls.Config{GetCertificate: s.GetCertificate, MinVersion: tls.VersionTLS12}
}

// Info describes the certificate in use.
func (s *CertStore) Info() CertInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.info
}

// OnChange registers a function to call after the certificate was replaced.
func (s *CertStore) OnChange(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = append(s.onChange, fn)
}

// Watch picks up a renewed certificate when the files it came from change,
// which is how certbot, acme.sh and the like deliver one.
func (s *CertStore) Watch(ctx context.Context, certPath, keyPath, origin string) {
	stamp := func() string {
		var out string
		for _, path := range []string{certPath, keyPath} {
			if fi, err := os.Stat(path); err == nil {
				out += fmt.Sprintf("%d/%d;", fi.ModTime().UnixNano(), fi.Size())
			}
		}
		return out
	}

	seen := stamp()
	ticker := time.NewTicker(certWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now := stamp()
		if now == seen {
			continue
		}
		// The two files are not replaced at the same instant: a pair that does
		// not match yet is tried again at the next tick.
		if err := s.Load(certPath, keyPath, origin); err != nil {
			log.Printf("the certificate files changed but cannot be used yet: %v", err)
			continue
		}
		seen = now
	}
}

// ensureSelfSigned returns the paths of a self-signed certificate and its key,
// creating the pair on first start. It is kept in the data directory so that
// browsers and mail clients only have to be told to trust it once.
func ensureSelfSigned(cfg Config) (certPath, keyPath string, err error) {
	certPath = filepath.Join(cfg.DataDir, "webui-cert.pem")
	keyPath = filepath.Join(cfg.DataDir, "webui-key.pem")

	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil && time.Now().Before(leaf.NotAfter.AddDate(0, -1, 0)) {
			return certPath, keyPath, nil
		}
	}

	log.Print("generating a self-signed certificate")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return "", "", err
	}

	names := []string{"mailbridge", "localhost"}
	if cfg.Hostname != "" {
		names = append(names, cfg.Hostname)
	}
	if h, err := os.Hostname(); err == nil {
		names = append(names, h)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mailbridge"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, n)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}

	return certPath, keyPath, nil
}
