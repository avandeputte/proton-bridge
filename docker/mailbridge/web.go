package main

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

const (
	sessionCookie = "mailbridge_session"
	csrfHeader    = "X-Mailbridge"
	maxBody       = 64 * 1024
)

type server struct {
	cfg    Config
	auth   *Auth
	bridge *Bridge
	syncer *SyncManager // nil unless Dovecot mode is on
	certs  *CertStore
	acme   *ACME // nil unless a Let's Encrypt certificate is configured
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeResult(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case errors.Is(err, ErrNotRunning):
		writeError(w, http.StatusServiceUnavailable, err.Error())
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return false
	}
	return true
}

func sessionToken(r *http.Request) string {
	if c, err := r.Cookie(sessionCookie); err == nil {
		return c.Value
	}
	return ""
}

// headers sets the security headers shared by every response.
func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// api wraps a handler that changes or reveals state. Requests that change
// state must carry a custom header, which browsers refuse to send cross-site
// without a CORS preflight that this server never approves.
func (s *server) api(authenticated bool, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Header.Get(csrfHeader) == "" {
			writeError(w, http.StatusForbidden, "missing "+csrfHeader+" header")
			return
		}
		if authenticated && !s.auth.Valid(sessionToken(r)) {
			writeError(w, http.StatusUnauthorized, "sign in required")
			return
		}
		fn(w, r)
	}
}

func (s *server) setCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.cfg.TLSMode == "on",
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()

	static, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /", http.FileServerFS(static))

	// Unauthenticated, reveals nothing but whether bridge is up.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if status := s.bridge.Snapshot().Status; status != "running" {
			http.Error(w, status, http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})

	// --- web UI session -----------------------------------------------------
	mux.HandleFunc("POST /api/session", s.api(false, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		token, err := s.auth.Login(req.Password)
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, ErrLocked) {
				status = http.StatusTooManyRequests
			}
			log.Printf("failed web UI sign-in from %s", r.RemoteAddr)
			writeError(w, status, err.Error())
			return
		}
		s.setCookie(w, token, int(sessionTTL.Seconds()))
		writeResult(w, nil)
	}))

	mux.HandleFunc("DELETE /api/session", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		s.auth.Logout(sessionToken(r))
		s.setCookie(w, "", -1)
		writeResult(w, nil)
	}))

	mux.HandleFunc("POST /api/password", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Current string `json:"current"`
			New     string `json:"new"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		writeResult(w, s.auth.Change(sessionToken(r), req.Current, req.New))
	}))

	// --- state ----------------------------------------------------------------
	mux.HandleFunc("GET /api/state", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		host := s.cfg.Hostname
		if host == "" {
			host = r.Host
			if h, _, err := net.SplitHostPort(r.Host); err == nil {
				host = h
			}
		}
		sync := map[string]SyncStatus{}
		if s.syncer != nil {
			sync = s.syncer.Status()
		}
		var acme *ACMEStatus
		if s.acme != nil {
			st := s.acme.Status()
			acme = &st
		}
		writeJSON(w, http.StatusOK, struct {
			State
			Connection        map[string]string     `json:"connection"`
			CanChangePassword bool                  `json:"canChangePassword"`
			Dovecot           bool                  `json:"dovecot"`
			Sync              map[string]SyncStatus `json:"sync"`
			Certificate       CertInfo              `json:"certificate"`
			MailCertificate   bool                  `json:"mailCertificate"`
			WebTLS            bool                  `json:"webTLS"`
			ACME              *ACMEStatus           `json:"acme,omitempty"`
		}{
			State: s.bridge.Snapshot(),
			Connection: map[string]string{
				"host":      host,
				"imapPort":  s.cfg.IMAPPort,
				"imapsPort": s.cfg.IMAPSPort,
				"smtpPort":  s.cfg.SMTPPort,
			},
			CanChangePassword: s.auth.CanChange(),
			Dovecot:           s.syncer != nil,
			Sync:              sync,
			Certificate:       s.certs.Info(),
			MailCertificate:   s.cfg.ManagedCert(),
			WebTLS:            s.cfg.TLSMode == "on",
			ACME:              acme,
		})
	}))

	mux.HandleFunc("GET /api/logs", s.api(true, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string][]string{"lines": s.bridge.Logs()})
	}))

	mux.HandleFunc("GET /api/certificate", s.api(true, func(w http.ResponseWriter, _ *http.Request) {
		cert, err := s.bridge.TLSCertificate()
		if err != nil {
			writeResult(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="proton-bridge-cert.pem"`)
		_, _ = w.Write(cert)
	}))

	mux.HandleFunc("DELETE /api/notices", s.api(true, func(w http.ResponseWriter, _ *http.Request) {
		s.bridge.ClearNotices()
		writeResult(w, nil)
	}))

	// --- Proton account sign-in -----------------------------------------------
	mux.HandleFunc("POST /api/login", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		req.Username = strings.TrimSpace(req.Username)
		if req.Username == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, "username and password are required")
			return
		}
		writeResult(w, s.bridge.Login(req.Username, req.Password))
	}))

	mux.HandleFunc("POST /api/login/2fa", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code string `json:"code"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		code := strings.ReplaceAll(strings.TrimSpace(req.Code), " ", "")
		if code == "" {
			writeError(w, http.StatusBadRequest, "enter the code from your authenticator app")
			return
		}
		writeResult(w, s.bridge.LoginTFA(code))
	}))

	mux.HandleFunc("POST /api/login/mailbox-password", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		if req.Password == "" {
			writeError(w, http.StatusBadRequest, "enter the mailbox password")
			return
		}
		writeResult(w, s.bridge.LoginMailboxPassword(req.Password))
	}))

	mux.HandleFunc("POST /api/login/verified", s.api(true, func(w http.ResponseWriter, _ *http.Request) {
		writeResult(w, s.bridge.LoginHVDone())
	}))

	mux.HandleFunc("DELETE /api/login", s.api(true, func(w http.ResponseWriter, _ *http.Request) {
		s.bridge.LoginAbort()
		writeResult(w, nil)
	}))

	// --- accounts ---------------------------------------------------------------
	mux.HandleFunc("POST /api/users/{id}/logout", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		writeResult(w, s.bridge.LogoutUser(r.PathValue("id")))
	}))

	mux.HandleFunc("DELETE /api/users/{id}", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		writeResult(w, s.bridge.RemoveUser(r.PathValue("id")))
	}))

	mux.HandleFunc("POST /api/users/{id}/split-mode", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Active bool `json:"active"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		writeResult(w, s.bridge.SetSplitMode(r.PathValue("id"), req.Active))
	}))

	// --- Dovecot mode sync ---------------------------------------------------------
	syncAction := func(action func(*SyncManager, string) error) http.HandlerFunc {
		return s.api(true, func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Login string `json:"login"`
			}
			if !readJSON(w, r, &req) {
				return
			}
			if s.syncer == nil {
				writeError(w, http.StatusBadRequest, "Dovecot mode is not enabled")
				return
			}
			writeResult(w, action(s.syncer, req.Login))
		})
	}
	mux.HandleFunc("POST /api/sync/run", syncAction((*SyncManager).SyncNow))
	mux.HandleFunc("POST /api/sync/approve", syncAction((*SyncManager).ApproveDeletions))
	mux.HandleFunc("POST /api/sync/rebuild", syncAction((*SyncManager).Rebuild))

	// --- bridge -------------------------------------------------------------------
	mux.HandleFunc("POST /api/settings", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		var req SettingsPatch
		if !readJSON(w, r, &req) {
			return
		}
		writeResult(w, s.bridge.ApplySettings(req))
	}))

	mux.HandleFunc("POST /api/bridge/restart", s.api(true, func(w http.ResponseWriter, _ *http.Request) {
		s.bridge.Restart()
		writeResult(w, nil)
	}))

	mux.HandleFunc("POST /api/bridge/repair", s.api(true, func(w http.ResponseWriter, _ *http.Request) {
		writeResult(w, s.bridge.Repair())
	}))

	return headers(mux)
}

func serveWeb(ctx context.Context, cfg Config, auth *Auth, bridge *Bridge, syncer *SyncManager, certs *CertStore, acme *ACME) error {
	s := &server{cfg: cfg, auth: auth, bridge: bridge, syncer: syncer, certs: certs, acme: acme}

	srv := &http.Server{
		Addr:              cfg.WebListen,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	ln, err := net.Listen("tcp", cfg.WebListen)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if cfg.TLSMode == "on" {
		srv.TLSConfig = certs.TLSConfig()
		log.Printf("web UI listening on https://%s", ln.Addr())
		err = srv.ServeTLS(ln, "", "")
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}

	log.Printf("web UI listening on http://%s (TLS is off: put a TLS-terminating reverse proxy in front)", ln.Addr())
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// healthcheck implements the container HEALTHCHECK: it asks the running
// instance whether bridge is up.
func healthcheck(cfg Config) error {
	_, port, err := net.SplitHostPort(cfg.WebListen)
	if err != nil {
		return err
	}
	scheme := "http"
	if cfg.TLSMode == "on" {
		scheme = "https"
	}
	client := &http.Client{
		Timeout: 4 * time.Second,
		// Loopback request to our own, usually self-signed, certificate.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
	}
	res, err := client.Get(scheme + "://" + net.JoinHostPort("127.0.0.1", port) + "/healthz")
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return errors.New("bridge is not running: " + res.Status)
	}
	return nil
}
