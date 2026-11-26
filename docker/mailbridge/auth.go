package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionTTL     = 12 * time.Hour
	minPasswordLen = 10
)

// Auth guards the web UI. The UI reveals mail credentials and accepts the
// Proton password, so nothing but the sign-in page is reachable without it.
type Auth struct {
	path  string // where the password hash is stored
	fixed bool   // password comes from the environment and cannot be changed in the UI

	mu        sync.Mutex
	hash      []byte
	sessions  map[string]time.Time
	failures  int
	lockedTil time.Time
}

type authFile struct {
	PasswordHash string `json:"passwordHash"`
}

func randomToken(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func NewAuth(cfg Config) (*Auth, error) {
	a := &Auth{
		path:     filepath.Join(cfg.DataDir, "webui.json"),
		sessions: map[string]time.Time{},
	}

	if cfg.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(cfg.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		a.hash, a.fixed = hash, true
		log.Print("web UI password taken from the environment")
		return a, nil
	}

	if data, err := os.ReadFile(a.path); err == nil {
		var f authFile
		if err := json.Unmarshal(data, &f); err == nil && f.PasswordHash != "" {
			a.hash = []byte(f.PasswordHash)
			return a, nil
		}
		log.Printf("ignoring unreadable %s", a.path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	// First start: generate a password and show it once in the container log.
	password := randomToken(15)
	if err := a.store(password); err != nil {
		return nil, err
	}
	log.Print("==================================================================")
	log.Print(" No web UI password is set. A random one was generated:")
	log.Print("")
	log.Printf("     %s", password)
	log.Print("")
	log.Print(" Sign in with it and change it under Settings. It is not shown again.")
	log.Print("==================================================================")
	return a, nil
}

func (a *Auth) store(password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	data, err := json.Marshal(authFile{PasswordHash: string(hash)})
	if err != nil {
		return err
	}
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, a.path); err != nil {
		return err
	}
	a.hash = hash
	return nil
}

// ErrLocked is returned while sign-in is throttled after failed attempts.
var ErrLocked = errors.New("too many failed attempts, wait a moment and try again")

// check verifies a password, throttling repeated failures. Callers hold a.mu.
func (a *Auth) check(password string) error {
	if time.Now().Before(a.lockedTil) {
		return ErrLocked
	}
	if bcrypt.CompareHashAndPassword(a.hash, []byte(password)) != nil {
		a.failures++
		if a.failures >= 3 {
			// 2s, 4s, 8s ... capped at five minutes.
			delay := time.Second << min(a.failures-2, 9)
			a.lockedTil = time.Now().Add(min(delay, 5*time.Minute))
		}
		return errors.New("wrong password")
	}
	a.failures = 0
	return nil
}

// Login exchanges the password for a session token.
func (a *Auth) Login(password string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := a.check(password); err != nil {
		return "", err
	}

	now := time.Now()
	for t, exp := range a.sessions {
		if now.After(exp) {
			delete(a.sessions, t)
		}
	}

	token := randomToken(32)
	a.sessions[token] = now.Add(sessionTTL)
	return token, nil
}

// Valid reports whether token is a live session.
func (a *Auth) Valid(token string) bool {
	if token == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	for t, exp := range a.sessions {
		if subtle.ConstantTimeCompare([]byte(t), []byte(token)) == 1 {
			if time.Now().After(exp) {
				delete(a.sessions, t)
				return false
			}
			return true
		}
	}
	return false
}

// Logout ends a session.
func (a *Auth) Logout(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, token)
}

// CanChange reports whether the password can be changed from the web UI.
func (a *Auth) CanChange() bool { return !a.fixed }

// Change replaces the password and signs out every other session.
func (a *Auth) Change(keepToken, current, next string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.fixed {
		return errors.New("the password is set through the container environment and cannot be changed here")
	}
	if len(next) < minPasswordLen {
		return errors.New("the new password must be at least 10 characters long")
	}
	if err := a.check(current); err != nil {
		if errors.Is(err, ErrLocked) {
			return err
		}
		return errors.New("the current password is wrong")
	}
	if err := a.store(next); err != nil {
		return err
	}
	for t := range a.sessions {
		if t != keepToken {
			delete(a.sessions, t)
		}
	}
	return nil
}
