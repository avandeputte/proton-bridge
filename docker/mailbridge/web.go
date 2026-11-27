package main

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
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
	acme   *ACME
	ports  *Ports
	public *Public
}

// mailHost is the server name mail clients are told to use: the one that
// was set, else a name the trusted certificate is good for, else the name of
// the reverse proxy or the one the browser used.
func (s *server) mailHost(r *http.Request) string {
	if host := s.public.Settings().Host; host != "" {
		return host
	}
	return s.defaultMailHost(r)
}

// defaultMailHost is the server name for mail clients while none is set in
// the web UI.
func (s *server) defaultMailHost(r *http.Request) string {
	if s.cfg.Hostname != "" {
		return s.cfg.Hostname
	}
	if name := s.certs.Hostname(); name != "" {
		return name
	}
	if u := s.public.URL(); u != nil {
		return u.Hostname()
	}
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		return h
	}
	return r.Host
}

// mailPort is the port mail clients are told to use for a service: the
// public one if it was set, else the one the container listens on. It is
// empty if the service is not offered.
func (s *server) mailPort(service string) string {
	if !s.ports.Offers(service) {
		return ""
	}
	if port := s.public.Port(service); port != 0 {
		return strconv.Itoa(port)
	}
	return s.ports.Shown(service)
}

// clientAddr is the address of the browser, for the log.
func (s *server) clientAddr(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" && s.public.URL() != nil {
		return fmt.Sprintf("%s (forwarded for %q)", r.RemoteAddr, fwd)
	}
	return r.RemoteAddr
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

// cookiePath is the path of the web UI as the browser sees it, which the
// page sends along with every request that changes something. Behind a
// reverse proxy it differs from the path of the request, and only the browser
// knows it for sure.
func cookiePath(r *http.Request) string {
	p := r.Header.Get(csrfHeader)
	if len(p) > 200 || !strings.HasPrefix(p, "/") || !strings.HasSuffix(p, "/") {
		return "/"
	}
	for _, c := range p {
		if c <= ' ' || c > '~' || c == ';' || c == ',' || c == '"' || c == '\\' {
			return "/"
		}
	}
	return p
}

// setCookie sets or removes the session cookie. The request tells where the
// browser is: on the container's own port or behind a reverse proxy, which
// may speak HTTPS when the container does not.
func (s *server) setCookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	// Browsers name the page a request comes from, and so say whether they
	// reach it with TLS. That counts, not how the request arrives here.
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	if origin := r.Header.Get("Origin"); origin != "" && origin != "null" {
		secure = strings.HasPrefix(origin, "https://")
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     cookiePath(r),
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// servedUnder is the context key for the sub-path a request arrived with.
type servedUnder struct{}

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
			log.Printf("failed web UI sign-in from %s", s.clientAddr(r))
			writeError(w, status, err.Error())
			return
		}
		s.setCookie(w, r, token, int(sessionTTL.Seconds()))
		writeResult(w, nil)
	}))

	mux.HandleFunc("DELETE /api/session", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		s.auth.Logout(sessionToken(r))
		s.setCookie(w, r, "", -1)
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
		sync := map[string]SyncStatus{}
		if s.syncer != nil {
			sync = s.syncer.Status()
		}
		var acme *ACMEStatus
		if st, ok := s.acme.Status(); ok {
			acme = &st
		}
		publicURL := ""
		if u := s.public.URL(); u != nil {
			publicURL = u.String()
		}
		envURL := ""
		if s.cfg.PublicURL != nil {
			envURL = s.cfg.PublicURL.String()
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
			PublicURL         string                `json:"publicURL"`
			ACME              *ACMEStatus           `json:"acme,omitempty"`
			ACMELocked        string                `json:"acmeLocked"`
			Ports             PortSettings          `json:"ports"`
			PortDefaults      map[string]string     `json:"portDefaults"`
			Public            PublicSettings        `json:"public"`
			PublicDefaults    map[string]string     `json:"publicDefaults"`
		}{
			State: s.bridge.Snapshot(),
			Connection: map[string]string{
				"host":      s.mailHost(r),
				"imapPort":  s.mailPort(svcIMAP),
				"imapsPort": s.mailPort(svcIMAPS),
				"smtpPort":  s.mailPort(svcSMTP),
			},
			CanChangePassword: s.auth.CanChange(),
			Dovecot:           s.syncer != nil,
			Sync:              sync,
			Certificate:       s.certs.Info(),
			MailCertificate:   s.certs.Trusted(),
			WebTLS:            s.cfg.TLSMode == "on",
			PublicURL:         publicURL,
			ACME:              acme,
			ACMELocked:        s.acme.Locked(),
			Ports:             s.ports.Settings(),
			PortDefaults: map[string]string{
				"imap": s.cfg.IMAPPort, "imaps": s.cfg.IMAPSPort, "smtp": s.cfg.SMTPPort,
			},
			Public: s.public.Settings(),
			// What applies while a field of the form is left empty.
			PublicDefaults: map[string]string{
				"url": envURL, "host": s.defaultMailHost(r),
				"imap": s.ports.Shown(svcIMAP), "imaps": s.ports.Shown(svcIMAPS), "smtp": s.ports.Shown(svcSMTP),
			},
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

	// One profile per Proton account sets up Mail on Apple devices. It
	// carries the bridge password, like the page it is downloaded from.
	mux.HandleFunc("GET /api/users/{id}/profile", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		var accounts []profileAccount
		for _, u := range s.bridge.Snapshot().Users {
			if u.ID != r.PathValue("id") || u.State != "connected" || len(u.Addresses) == 0 || u.Password == "" {
				continue
			}
			addresses := u.Addresses[:1]
			if u.SplitMode {
				addresses = u.Addresses
			}
			for _, a := range addresses {
				accounts = append(accounts, profileAccount{Address: a, Password: u.Password})
			}
		}
		if len(accounts) == 0 {
			writeError(w, http.StatusNotFound, "this account is not signed in")
			return
		}
		// A port of its own for SSL/TLS leaves no doubt about how to connect.
		imap := s.mailPort(svcIMAPS)
		if imap == "" {
			imap = s.mailPort(svcIMAP)
		}
		imapPort, err1 := strconv.Atoi(imap)
		smtpPort, err2 := strconv.Atoi(s.mailPort(svcSMTP))
		if err1 != nil || err2 != nil {
			writeError(w, http.StatusConflict, "IMAP or SMTP is turned off in this container")
			return
		}
		name := profileID(accounts[0].Address) + ".mobileconfig"
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		_, _ = w.Write(appleMailProfile(s.mailHost(r), imapPort, smtpPort, accounts))
	}))

	// --- certificate from Let's Encrypt ----------------------------------------------
	mux.HandleFunc("GET /api/acme", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		settings := s.acme.Settings()
		// The values stay here: the page only learns which ones are set.
		set := make([]string, 0, len(settings.Variables))
		for name := range settings.Variables {
			set = append(set, name)
		}
		sort.Strings(set)
		providers, err := s.acme.Providers(r.Context())
		if err != nil {
			log.Print(err)
			providers = []string{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"locked":    s.acme.Locked(),
			"domains":   append([]string{}, settings.Domains...),
			"dns":       settings.DNS,
			"email":     settings.Email,
			"staging":   settings.Staging,
			"resolvers": append([]string{}, settings.Resolvers...),
			"set":       set,
			"providers": providers,
		})
	}))

	mux.HandleFunc("GET /api/acme/providers/{code}", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		info, err := s.acme.Provider(r.Context(), r.PathValue("code"))
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, info)
	}))

	mux.HandleFunc("POST /api/acme", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ACMESettings
			Keep []string `json:"keep"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		if len(req.Domains) == 0 {
			writeError(w, http.StatusBadRequest, "enter the domain name to get the certificate for")
			return
		}
		writeResult(w, s.acme.Configure(r.Context(), req.ACMESettings, req.Keep))
	}))

	mux.HandleFunc("DELETE /api/acme", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		writeResult(w, s.acme.Configure(r.Context(), ACMESettings{}, nil))
	}))

	mux.HandleFunc("POST /api/acme/retry", s.api(true, func(w http.ResponseWriter, _ *http.Request) {
		s.acme.Retry()
		writeResult(w, nil)
	}))

	// --- ports and addresses for mail clients and browsers ------------------------
	mux.HandleFunc("POST /api/addresses", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Ports  PortSettings   `json:"ports"`
			Public PublicSettings `json:"public"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		u, err := req.Public.check()
		if err != nil {
			writeResult(w, err)
			return
		}
		// A reverse proxy that passes the path on as it is only finds the
		// page under the path of the public address. Changing that path
		// from behind such a proxy would cut the page off from itself.
		if u == nil {
			u = s.cfg.PublicURL
		}
		was, _ := r.Context().Value(servedUnder{}).(string)
		if was != "" && (u == nil || strings.TrimRight(u.Path, "/") != was) {
			writeError(w, http.StatusBadRequest, "this page is reached under "+was+" right now, and would stop working there "+
				"with another path in its address. To change the path, open the page at the container's own address")
			return
		}
		if req.Public.IMAPS != 0 && !s.ports.Offers(svcIMAPS) {
			writeError(w, http.StatusBadRequest, "IMAP over SSL/TLS on a port of its own needs Dovecot mode")
			return
		}
		if err := s.ports.Set(req.Ports); err != nil {
			writeResult(w, err)
			return
		}
		writeResult(w, s.public.Set(req.Public))
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

	handler := headers(mux)
	// Under a sub-path of a reverse proxy. Some proxies pass the path on as
	// it is, others cut the prefix off: both work, and so does the
	// container's own address.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := s.public.BasePath()
		switch {
		case base != "" && r.URL.Path == base:
			http.Redirect(w, r, base+"/", http.StatusPermanentRedirect)
		case base != "" && strings.HasPrefix(r.URL.Path, base+"/"):
			r = r.WithContext(context.WithValue(r.Context(), servedUnder{}, base))
			http.StripPrefix(base, handler).ServeHTTP(w, r)
		default:
			handler.ServeHTTP(w, r)
		}
	})
}

func serveWeb(ctx context.Context, s *server) error {
	cfg := s.cfg

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
		newWebTrouble(s.certs, s.public.URL, s.bridge.notify).watch(srv)
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
