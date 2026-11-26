package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "mailbridge/internal/bridgepb"
)

const (
	bridgeHost       = "127.0.0.1" // the only address bridge ever binds to
	defaultIMAPPort  = 1143
	defaultSMTPPort  = 1025
	rpcTimeout       = 15 * time.Second
	maxNotices       = 20
	logRingLines     = 400
	serverConfigFile = "grpcServerConfig.json"
)

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// ErrNotRunning is returned by every action while bridge is (re)starting.
var ErrNotRunning = errors.New("bridge is not running yet, try again in a moment")

// User is one Proton account known to bridge.
type User struct {
	ID         string   `json:"id"`
	Username   string   `json:"username"`
	State      string   `json:"state"` // connected, locked, signedOut
	SplitMode  bool     `json:"splitMode"`
	UsedBytes  int64    `json:"usedBytes"`
	TotalBytes int64    `json:"totalBytes"`
	Password   string   `json:"password"` // bridge-generated IMAP/SMTP password
	Addresses  []string `json:"addresses"`
	Syncing    bool     `json:"syncing"`
	Progress   float64  `json:"progress"`
}

// Settings mirrors the bridge settings the web UI can change.
type Settings struct {
	IMAPPort          int    `json:"imapPort"`
	SMTPPort          int    `json:"smtpPort"`
	IMAPSSL           bool   `json:"imapSSL"`
	SMTPSSL           bool   `json:"smtpSSL"`
	AllMailVisible    bool   `json:"allMailVisible"`
	TelemetryDisabled bool   `json:"telemetryDisabled"`
	DoHEnabled        bool   `json:"dohEnabled"`
	Keychain          string `json:"keychain"`
}

// LoginState tracks the single in-flight "add account" flow.
type LoginState struct {
	// Stage is one of: idle, working, tfa, mailboxPassword, hv, done, error.
	Stage    string `json:"stage"`
	Username string `json:"username,omitempty"`
	Message  string `json:"message,omitempty"`
	HVURL    string `json:"hvUrl,omitempty"`
}

// Notice is a message from bridge worth showing to the user.
type Notice struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"` // info, warn, error
	Message string    `json:"message"`
}

// State is the snapshot the web UI renders.
type State struct {
	Status   string     `json:"status"` // starting, running, stopped
	Version  string     `json:"version"`
	Online   bool       `json:"online"`
	Users    []User     `json:"users"`
	Settings Settings   `json:"settings"`
	Login    LoginState `json:"login"`
	Notices  []Notice   `json:"notices"`
}

type syncState struct {
	syncing  bool
	progress float64
}

// Bridge supervises the bridge process and talks to its gRPC frontend API.
type Bridge struct {
	cfg Config

	mu       sync.RWMutex
	status   string
	version  string
	online   bool
	users    []User
	settings Settings
	login    LoginState
	loginPw  []byte // kept only while a login is in flight (human verification needs a retry)
	sync     map[string]syncState
	notices  []Notice
	client   pb.BridgeClient

	logMu sync.Mutex
	logs  []string

	restartCh chan struct{}
}

func NewBridge(cfg Config) *Bridge {
	return &Bridge{
		cfg:       cfg,
		status:    "starting",
		online:    true,
		login:     LoginState{Stage: "idle"},
		sync:      map[string]syncState{},
		settings:  Settings{IMAPPort: defaultIMAPPort, SMTPPort: defaultSMTPPort},
		restartCh: make(chan struct{}, 1),
	}
}

// IMAPTarget is where the LAN-facing IMAP port forwards to.
func (b *Bridge) IMAPTarget() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return net.JoinHostPort(bridgeHost, strconv.Itoa(b.settings.IMAPPort))
}

// SMTPTarget is where the LAN-facing SMTP port forwards to.
func (b *Bridge) SMTPTarget() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return net.JoinHostPort(bridgeHost, strconv.Itoa(b.settings.SMTPPort))
}

// MailAccounts lists the IMAP logins bridge currently serves, for Dovecot mode.
func (b *Bridge) MailAccounts() []MailAccount {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.status != "running" {
		return nil
	}

	var out []MailAccount
	for _, u := range b.users {
		if u.State != "connected" || len(u.Addresses) == 0 {
			continue
		}
		logins := u.Addresses[:1]
		if u.SplitMode {
			logins = u.Addresses
		}
		for _, login := range logins {
			out = append(out, MailAccount{Login: login, Password: u.Password, Ready: !b.sync[u.ID].syncing})
		}
	}
	return out
}

// IMAPEndpoint is where bridge's own IMAP server listens.
func (b *Bridge) IMAPEndpoint() (string, int, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return bridgeHost, b.settings.IMAPPort, b.settings.IMAPSSL
}

// Snapshot returns a copy of the current state for the web UI.
func (b *Bridge) Snapshot() State {
	b.mu.RLock()
	defer b.mu.RUnlock()

	users := make([]User, len(b.users))
	for i, u := range b.users {
		if s, ok := b.sync[u.ID]; ok {
			u.Syncing, u.Progress = s.syncing, s.progress
		}
		users[i] = u
	}

	notices := make([]Notice, len(b.notices))
	copy(notices, b.notices)

	return State{
		Status:   b.status,
		Version:  b.version,
		Online:   b.online,
		Users:    users,
		Settings: b.settings,
		Login:    b.login,
		Notices:  notices,
	}
}

// Logs returns the most recent bridge log lines.
func (b *Bridge) Logs() []string {
	b.logMu.Lock()
	defer b.logMu.Unlock()
	return append([]string(nil), b.logs...)
}

func (b *Bridge) addLog(line string) {
	b.logMu.Lock()
	defer b.logMu.Unlock()
	b.logs = append(b.logs, line)
	if len(b.logs) > logRingLines {
		b.logs = b.logs[len(b.logs)-logRingLines:]
	}
}

func (b *Bridge) notify(level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("notice (%s): %s", level, msg)

	b.mu.Lock()
	defer b.mu.Unlock()
	if n := len(b.notices); n > 0 && b.notices[n-1].Message == msg {
		b.notices[n-1].Time = time.Now()
		return
	}
	b.notices = append(b.notices, Notice{Time: time.Now(), Level: level, Message: msg})
	if len(b.notices) > maxNotices {
		b.notices = b.notices[len(b.notices)-maxNotices:]
	}
}

// ClearNotices dismisses all notices.
func (b *Bridge) ClearNotices() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.notices = nil
}

func (b *Bridge) setLogin(l LoginState) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.login = l
	if l.Stage == "idle" || l.Stage == "done" || l.Stage == "error" {
		for i := range b.loginPw {
			b.loginPw[i] = 0
		}
		b.loginPw = nil
	}
}

func (b *Bridge) getClient() (pb.BridgeClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.client == nil {
		return nil, ErrNotRunning
	}
	return b.client, nil
}

func rpcCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), rpcTimeout)
}

// ---------------------------------------------------------------------------
// Process supervision
// ---------------------------------------------------------------------------

// Run keeps bridge running until ctx is cancelled.
func (b *Bridge) Run(ctx context.Context) {
	for ctx.Err() == nil {
		err := b.runOnce(ctx)

		b.mu.Lock()
		b.client = nil
		b.status = "stopped"
		b.sync = map[string]syncState{}
		b.mu.Unlock()
		b.setLogin(LoginState{Stage: "idle"})

		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("bridge stopped: %v; restarting in 3s", err)
		} else {
			log.Print("bridge stopped; restarting in 3s")
		}

		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
		}

		b.mu.Lock()
		b.status = "starting"
		b.mu.Unlock()
	}
}

// Restart asks the supervisor to stop bridge; Run starts it again.
func (b *Bridge) Restart() {
	select {
	case b.restartCh <- struct{}{}:
	default:
	}
}

type serverConfig struct {
	Port           int    `json:"port"`
	Cert           string `json:"cert"`
	Token          string `json:"token"`
	FileSocketPath string `json:"fileSocketPath"`
}

func (b *Bridge) serverConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "protonmail", "bridge-v3", serverConfigFile), nil
}

func (b *Bridge) runOnce(ctx context.Context) error {
	cfgPath, err := b.serverConfigPath()
	if err != nil {
		return err
	}
	// A stale file from a previous run would point us at a dead socket.
	if err := os.Remove(cfgPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot remove stale %s: %w", cfgPath, err)
	}
	// We are the only thing that ever starts bridge in this container, so a
	// lock file can only be a leftover of a killed container. Its recorded PID
	// may belong to an unrelated process now, which would block start-up.
	if cache, err := os.UserCacheDir(); err == nil {
		locks, _ := filepath.Glob(filepath.Join(cache, "protonmail", "bridge-v3", "*.lock"))
		for _, lock := range locks {
			_ = os.Remove(lock)
		}
	}
	// Drain a restart request that raced with the previous exit.
	select {
	case <-b.restartCh:
	default:
	}

	// #nosec G204 -- the binary path comes from the container configuration.
	cmd := exec.Command(b.cfg.BridgeBin,
		"--grpc",
		"--no-window",
		"--parent-pid", strconv.Itoa(os.Getpid()),
		"--log-level", b.cfg.LogLevel,
	)
	cmd.Stdin = nil
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw

	go func() {
		scanner := bufio.NewScanner(pr)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := ansiEscape.ReplaceAllString(scanner.Text(), "")
			fmt.Fprintln(os.Stdout, "[bridge] "+line)
			b.addLog(line)
		}
	}()

	log.Printf("starting %s --grpc", b.cfg.BridgeBin)
	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		return fmt.Errorf("cannot start bridge: %w", err)
	}

	exited := make(chan error, 1)
	go func() {
		exited <- cmd.Wait()
		_ = pw.Close()
	}()

	stop := func(client pb.BridgeClient) {
		if client != nil {
			qctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, _ = client.Quit(qctx, &emptypb.Empty{})
			cancel()
		} else {
			_ = cmd.Process.Signal(syscall.SIGTERM)
		}
		select {
		case <-exited:
			return
		case <-time.After(20 * time.Second):
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
	}

	// Wait for bridge to publish its gRPC endpoint.
	var sc serverConfig
	deadline := time.After(3 * time.Minute)
waitConfig:
	for {
		if data, err := os.ReadFile(cfgPath); err == nil { //nolint:gosec
			if err := json.Unmarshal(data, &sc); err == nil && sc.Token != "" {
				break waitConfig
			}
		}
		select {
		case err := <-exited:
			return fmt.Errorf("bridge exited during start-up: %v", err)
		case <-ctx.Done():
			stop(nil)
			return nil
		case <-b.restartCh:
			stop(nil)
			return nil
		case <-deadline:
			stop(nil)
			return errors.New("bridge did not publish its gRPC endpoint within 3 minutes")
		case <-time.After(200 * time.Millisecond):
		}
	}

	conn, err := dial(sc)
	if err != nil {
		stop(nil)
		return err
	}
	defer func() { _ = conn.Close() }()
	client := pb.NewBridgeClient(conn)

	// Bridge quits as soon as its event stream is closed, so the stream lives
	// exactly as long as this function.
	streamCtx, cancelStream := context.WithCancel(context.Background())
	defer cancelStream()

	stream, err := client.RunEventStream(streamCtx, &pb.EventStreamRequest{ClientPlatform: "Docker"})
	if err != nil {
		stop(client)
		return fmt.Errorf("cannot open bridge event stream: %w", err)
	}

	streamDone := make(chan error, 1)
	go func() {
		for {
			ev, err := stream.Recv()
			if err != nil {
				streamDone <- err
				return
			}
			b.handleEvent(client, ev)
		}
	}()

	b.mu.Lock()
	b.client = client
	b.mu.Unlock()

	b.initSession(client)

	b.mu.Lock()
	b.status = "running"
	b.mu.Unlock()
	log.Printf("bridge %s is running", b.Snapshot().Version)

	// Bridge only tells us about changes; poll occasionally as a safety net.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case err := <-exited:
			return fmt.Errorf("bridge exited: %v", err)
		case err := <-streamDone:
			stop(client)
			return fmt.Errorf("bridge event stream closed: %v", err)
		case <-b.restartCh:
			log.Print("restart requested")
			stop(client)
			return nil
		case <-ctx.Done():
			log.Print("stopping bridge")
			stop(client)
			return nil
		case <-ticker.C:
			b.refreshUsers(client)
		}
	}
}

type tokenCreds string

func (t tokenCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"server-token": string(t)}, nil
}

func (tokenCreds) RequireTransportSecurity() bool { return true }

func dial(sc serverConfig) (*grpc.ClientConn, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(sc.Cert)) {
		return nil, errors.New("bridge published an invalid gRPC certificate")
	}

	target := net.JoinHostPort(bridgeHost, strconv.Itoa(sc.Port))
	if sc.FileSocketPath != "" {
		target = "unix://" + sc.FileSocketPath
	}

	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs:    pool,
			ServerName: bridgeHost, // the certificate is issued for 127.0.0.1
			MinVersion: tls.VersionTLS12,
		})),
		grpc.WithPerRPCCredentials(tokenCreds(sc.Token)),
		grpc.WithAuthority(bridgeHost),
	)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to bridge: %w", err)
	}
	return conn, nil
}

func (b *Bridge) initSession(client pb.BridgeClient) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if _, err := client.GuiReady(ctx, &emptypb.Empty{}); err != nil {
		log.Printf("GuiReady failed: %v", err)
	}
	if v, err := client.Version(ctx, &emptypb.Empty{}); err == nil {
		b.mu.Lock()
		b.version = v.GetValue()
		b.mu.Unlock()
	}
	// Bridge cannot update itself here: the image is the unit of update.
	if _, err := client.SetIsAutomaticUpdateOn(ctx, wrapperspb.Bool(false)); err != nil {
		log.Printf("could not disable automatic updates: %v", err)
	}

	b.refreshSettings(client)
	b.refreshUsers(client)
}

// ---------------------------------------------------------------------------
// State refresh
// ---------------------------------------------------------------------------

func stateName(s pb.UserState) string {
	switch s {
	case pb.UserState_CONNECTED:
		return "connected"
	case pb.UserState_LOCKED:
		return "locked"
	default:
		return "signedOut"
	}
}

func (b *Bridge) refreshUsers(client pb.BridgeClient) {
	ctx, cancel := rpcCtx()
	defer cancel()

	list, err := client.GetUserList(ctx, &emptypb.Empty{})
	if err != nil {
		log.Printf("could not list accounts: %v", err)
		return
	}

	users := make([]User, 0, len(list.GetUsers()))
	for _, u := range list.GetUsers() {
		users = append(users, User{
			ID:         u.GetId(),
			Username:   u.GetUsername(),
			State:      stateName(u.GetState()),
			SplitMode:  u.GetSplitMode(),
			UsedBytes:  u.GetUsedBytes(),
			TotalBytes: u.GetTotalBytes(),
			Password:   string(u.GetPassword()),
			Addresses:  u.GetAddresses(),
		})
	}

	b.mu.Lock()
	b.users = users
	b.mu.Unlock()
}

func (b *Bridge) refreshSettings(client pb.BridgeClient) {
	ctx, cancel := rpcCtx()
	defer cancel()

	b.mu.RLock()
	s := b.settings
	b.mu.RUnlock()

	if m, err := client.MailServerSettings(ctx, &emptypb.Empty{}); err == nil {
		s.IMAPPort, s.SMTPPort = int(m.GetImapPort()), int(m.GetSmtpPort())
		s.IMAPSSL, s.SMTPSSL = m.GetUseSSLForImap(), m.GetUseSSLForSmtp()
	} else {
		log.Printf("could not read mail server settings: %v", err)
	}
	if v, err := client.IsAllMailVisible(ctx, &emptypb.Empty{}); err == nil {
		s.AllMailVisible = v.GetValue()
	}
	if v, err := client.IsTelemetryDisabled(ctx, &emptypb.Empty{}); err == nil {
		s.TelemetryDisabled = v.GetValue()
	}
	if v, err := client.IsDoHEnabled(ctx, &emptypb.Empty{}); err == nil {
		s.DoHEnabled = v.GetValue()
	}
	if v, err := client.CurrentKeychain(ctx, &emptypb.Empty{}); err == nil {
		s.Keychain = v.GetValue()
	}

	b.mu.Lock()
	b.settings = s
	b.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

func (b *Bridge) handleEvent(client pb.BridgeClient, ev *pb.StreamEvent) {
	switch e := ev.GetEvent().(type) {
	case *pb.StreamEvent_Login:
		b.handleLoginEvent(client, e.Login)

	case *pb.StreamEvent_User:
		b.handleUserEvent(client, e.User)

	case *pb.StreamEvent_App:
		switch a := e.App.GetEvent().(type) {
		case *pb.AppEvent_InternetStatus:
			b.mu.Lock()
			b.online = a.InternetStatus.GetConnected()
			b.mu.Unlock()
		case *pb.AppEvent_AllUsersLoaded:
			b.refreshUsers(client)
		case *pb.AppEvent_UserNotification:
			n := a.UserNotification
			b.notify("info", "%s %s %s", n.GetTitle(), n.GetSubtitle(), n.GetBody())
		case *pb.AppEvent_RepairStarted:
			b.notify("info", "Repair started: bridge is re-synchronising all accounts.")
		case *pb.AppEvent_ResetFinished:
			b.refreshUsers(client)
			b.refreshSettings(client)
		}

	case *pb.StreamEvent_MailServerSettings:
		switch m := e.MailServerSettings.GetEvent().(type) {
		case *pb.MailServerSettingsEvent_Error:
			b.notify("error", "Bridge could not apply the mail server settings (%s).", m.Error.GetType())
		default:
			b.refreshSettings(client)
		}

	case *pb.StreamEvent_Keychain:
		if _, ok := e.Keychain.GetEvent().(*pb.KeychainEvent_HasNoKeychain); ok {
			b.notify("error", "Bridge could not use the keychain. Account credentials are stored without encryption; check the container logs.")
		}

	case *pb.StreamEvent_Mail:
		switch e.Mail.GetEvent().(type) {
		case *pb.MailEvent_ApiCertIssue:
			b.notify("error", "Bridge could not verify the identity of the Proton servers (TLS certificate issue). Mail is not being synchronised.")
		default:
			b.refreshUsers(client)
		}

	case *pb.StreamEvent_Update:
		if f, ok := e.Update.GetEvent().(*pb.UpdateEvent_Force); ok {
			b.notify("error", "This bridge version is no longer supported by Proton (latest is %s). Rebuild the container image from a newer source.", f.Force.GetVersion())
		}

	case *pb.StreamEvent_GenericError:
		b.notify("error", "Bridge reported an error: %s.", e.GenericError.GetCode())
	}
}

func (b *Bridge) handleUserEvent(client pb.BridgeClient, ev *pb.UserEvent) {
	setSync := func(id string, s syncState) {
		b.mu.Lock()
		b.sync[id] = s
		b.mu.Unlock()
	}

	switch u := ev.GetEvent().(type) {
	case *pb.UserEvent_SyncStartedEvent:
		setSync(u.SyncStartedEvent.GetUserID(), syncState{syncing: true})
	case *pb.UserEvent_SyncProgressEvent:
		setSync(u.SyncProgressEvent.GetUserID(), syncState{syncing: true, progress: u.SyncProgressEvent.GetProgress()})
	case *pb.UserEvent_SyncFinishedEvent:
		setSync(u.SyncFinishedEvent.GetUserID(), syncState{})
		b.refreshUsers(client)
	case *pb.UserEvent_ImapLoginFailedEvent:
		b.notify("warn", "A mail client tried to sign in as %q with a wrong password. Use the bridge password shown for the account, not the Proton password.", u.ImapLoginFailedEvent.GetUsername())
	case *pb.UserEvent_UserBadEvent:
		id := u.UserBadEvent.GetUserID()
		b.notify("warn", "Bridge hit an inconsistent state for an account (%s) and is re-synchronising it.", u.UserBadEvent.GetErrorMessage())
		go func() {
			ctx, cancel := rpcCtx()
			defer cancel()
			if _, err := client.SendBadEventUserFeedback(ctx, &pb.UserBadEventFeedbackRequest{UserID: id, DoResync: true}); err != nil {
				log.Printf("could not request resync: %v", err)
			}
		}()
	case *pb.UserEvent_UserDisconnected:
		b.notify("warn", "Account %s was signed out by Proton. Sign in again to resume mail access.", u.UserDisconnected.GetUsername())
		b.refreshUsers(client)
	default:
		b.refreshUsers(client)
	}
}

func (b *Bridge) handleLoginEvent(client pb.BridgeClient, ev *pb.LoginEvent) {
	b.mu.RLock()
	username := b.login.Username
	b.mu.RUnlock()

	switch l := ev.GetEvent().(type) {
	case *pb.LoginEvent_TfaRequested, *pb.LoginEvent_TfaOrFidoRequested:
		b.setLogin(LoginState{Stage: "tfa", Username: username})

	case *pb.LoginEvent_TwoPasswordRequested:
		b.setLogin(LoginState{Stage: "mailboxPassword", Username: username})

	case *pb.LoginEvent_HvRequested:
		b.setLogin(LoginState{Stage: "hv", Username: username, HVURL: l.HvRequested.GetHvUrl()})

	case *pb.LoginEvent_FidoRequested:
		b.abortLogin(client, username)
		b.setLogin(LoginState{Stage: "error", Username: username,
			Message: "This account only allows a security key as second factor, which a container cannot use. Add an authenticator app (TOTP) to the Proton account and try again."})

	case *pb.LoginEvent_Finished:
		b.refreshUsers(client)
		b.setLogin(LoginState{Stage: "done", Username: username, Message: "Signed in. Bridge is now synchronising the mailbox."})

	case *pb.LoginEvent_AlreadyLoggedIn:
		b.refreshUsers(client)
		b.setLogin(LoginState{Stage: "done", Username: username, Message: "This account is already signed in."})

	case *pb.LoginEvent_Error:
		msg := l.Error.GetMessage()
		switch l.Error.GetType() {
		case pb.LoginErrorType_TFA_ERROR:
			b.setLogin(LoginState{Stage: "tfa", Username: username, Message: "That code was not accepted. Try again."})
			return
		case pb.LoginErrorType_TWO_PASSWORDS_ERROR:
			b.setLogin(LoginState{Stage: "mailboxPassword", Username: username, Message: "That mailbox password was not accepted. Try again."})
			return
		case pb.LoginErrorType_USERNAME_PASSWORD_ERROR:
			if msg == "" {
				msg = "Incorrect username or password."
			}
		case pb.LoginErrorType_FREE_USER:
			msg = "Proton Mail Bridge requires a paid Proton plan."
		case pb.LoginErrorType_CONNECTION_ERROR:
			if msg == "" {
				msg = "Could not reach the Proton servers."
			}
		case pb.LoginErrorType_HV_ERROR:
			if msg == "" {
				msg = "Human verification failed."
			}
		default:
			if msg == "" {
				msg = "Sign-in was aborted. Please start again."
			}
		}
		b.setLogin(LoginState{Stage: "error", Username: username, Message: msg})
	}
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

func b64(in []byte) []byte {
	out := make([]byte, base64.StdEncoding.EncodedLen(len(in)))
	base64.StdEncoding.Encode(out, in)
	return out
}

// Login starts adding a Proton account.
func (b *Bridge) Login(username, password string) error {
	client, err := b.getClient()
	if err != nil {
		return err
	}

	b.mu.Lock()
	switch b.login.Stage {
	case "working", "tfa", "mailboxPassword", "hv":
		b.mu.Unlock()
		return errors.New("another sign-in is already in progress")
	}
	b.login = LoginState{Stage: "working", Username: username}
	b.loginPw = []byte(password)
	b.mu.Unlock()

	ctx, cancel := rpcCtx()
	defer cancel()
	if _, err := client.Login(ctx, &pb.LoginRequest{Username: username, Password: b64([]byte(password))}); err != nil {
		b.setLogin(LoginState{Stage: "error", Username: username, Message: err.Error()})
		return err
	}
	return nil
}

func (b *Bridge) loginStep(stage string, call func(pb.BridgeClient, context.Context, string) error) error {
	client, err := b.getClient()
	if err != nil {
		return err
	}

	b.mu.Lock()
	if b.login.Stage != stage {
		b.mu.Unlock()
		return errors.New("the sign-in is not waiting for this step")
	}
	username := b.login.Username
	b.login = LoginState{Stage: "working", Username: username}
	b.mu.Unlock()

	ctx, cancel := rpcCtx()
	defer cancel()
	if err := call(client, ctx, username); err != nil {
		b.setLogin(LoginState{Stage: "error", Username: username, Message: err.Error()})
		return err
	}
	return nil
}

// LoginTFA submits the authenticator code.
func (b *Bridge) LoginTFA(code string) error {
	return b.loginStep("tfa", func(c pb.BridgeClient, ctx context.Context, username string) error {
		_, err := c.Login2FA(ctx, &pb.LoginRequest{Username: username, Password: b64([]byte(code))})
		return err
	})
}

// LoginMailboxPassword submits the second (mailbox) password of two-password accounts.
func (b *Bridge) LoginMailboxPassword(password string) error {
	return b.loginStep("mailboxPassword", func(c pb.BridgeClient, ctx context.Context, username string) error {
		_, err := c.Login2Passwords(ctx, &pb.LoginRequest{Username: username, Password: b64([]byte(password))})
		return err
	})
}

// LoginHVDone retries the login after the user solved the human verification.
func (b *Bridge) LoginHVDone() error {
	b.mu.RLock()
	pw := append([]byte(nil), b.loginPw...)
	b.mu.RUnlock()

	return b.loginStep("hv", func(c pb.BridgeClient, ctx context.Context, username string) error {
		useHV := true
		_, err := c.Login(ctx, &pb.LoginRequest{Username: username, Password: b64(pw), UseHvDetails: &useHV})
		return err
	})
}

func (b *Bridge) abortLogin(client pb.BridgeClient, username string) {
	ctx, cancel := rpcCtx()
	defer cancel()
	if _, err := client.LoginAbort(ctx, &pb.LoginAbortRequest{Username: username}); err != nil {
		log.Printf("could not abort login: %v", err)
	}
}

// LoginAbort cancels the in-flight sign-in, or dismisses its result.
func (b *Bridge) LoginAbort() {
	b.mu.RLock()
	stage, username := b.login.Stage, b.login.Username
	b.mu.RUnlock()

	if stage != "idle" && stage != "done" && stage != "error" {
		if client, err := b.getClient(); err == nil {
			b.abortLogin(client, username)
		}
	}
	b.setLogin(LoginState{Stage: "idle"})
}

func (b *Bridge) hasUser(id string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, u := range b.users {
		if u.ID == id {
			return true
		}
	}
	return false
}

func (b *Bridge) userAction(id string, call func(pb.BridgeClient, context.Context) error) error {
	client, err := b.getClient()
	if err != nil {
		return err
	}
	if !b.hasUser(id) {
		return errors.New("unknown account")
	}

	ctx, cancel := rpcCtx()
	defer cancel()
	if err := call(client, ctx); err != nil {
		return err
	}

	// These calls return before bridge has finished; the event stream normally
	// reports the change, this is a fallback.
	go func() {
		time.Sleep(2 * time.Second)
		b.refreshUsers(client)
	}()
	return nil
}

// LogoutUser signs an account out but keeps its local data.
func (b *Bridge) LogoutUser(id string) error {
	return b.userAction(id, func(c pb.BridgeClient, ctx context.Context) error {
		_, err := c.LogoutUser(ctx, wrapperspb.String(id))
		return err
	})
}

// RemoveUser signs an account out and deletes its local data.
func (b *Bridge) RemoveUser(id string) error {
	return b.userAction(id, func(c pb.BridgeClient, ctx context.Context) error {
		_, err := c.RemoveUser(ctx, wrapperspb.String(id))
		return err
	})
}

// SetSplitMode switches an account between combined and split address mode.
func (b *Bridge) SetSplitMode(id string, active bool) error {
	return b.userAction(id, func(c pb.BridgeClient, ctx context.Context) error {
		_, err := c.SetUserSplitMode(ctx, &pb.UserSplitModeRequest{UserID: id, Active: active})
		return err
	})
}

// SettingsPatch carries the settings the web UI wants changed; nil = unchanged.
type SettingsPatch struct {
	IMAPSSL           *bool `json:"imapSSL"`
	SMTPSSL           *bool `json:"smtpSSL"`
	AllMailVisible    *bool `json:"allMailVisible"`
	TelemetryDisabled *bool `json:"telemetryDisabled"`
	DoHEnabled        *bool `json:"dohEnabled"`
}

// ApplySettings changes bridge settings.
func (b *Bridge) ApplySettings(p SettingsPatch) error {
	client, err := b.getClient()
	if err != nil {
		return err
	}

	b.mu.RLock()
	cur := b.settings
	b.mu.RUnlock()

	ctx, cancel := rpcCtx()
	defer cancel()

	var errs []error

	imapSSL, smtpSSL := cur.IMAPSSL, cur.SMTPSSL
	if p.IMAPSSL != nil {
		imapSSL = *p.IMAPSSL
	}
	if p.SMTPSSL != nil {
		smtpSSL = *p.SMTPSSL
	}
	if imapSSL != cur.IMAPSSL || smtpSSL != cur.SMTPSSL {
		_, err := client.SetMailServerSettings(ctx, &pb.ImapSmtpSettings{
			ImapPort:      int32(cur.IMAPPort), //nolint:gosec
			SmtpPort:      int32(cur.SMTPPort), //nolint:gosec
			UseSSLForImap: imapSSL,
			UseSSLForSmtp: smtpSSL,
		})
		errs = append(errs, err)
	}
	if p.AllMailVisible != nil && *p.AllMailVisible != cur.AllMailVisible {
		_, err := client.SetIsAllMailVisible(ctx, wrapperspb.Bool(*p.AllMailVisible))
		errs = append(errs, err)
	}
	if p.TelemetryDisabled != nil && *p.TelemetryDisabled != cur.TelemetryDisabled {
		_, err := client.SetIsTelemetryDisabled(ctx, wrapperspb.Bool(*p.TelemetryDisabled))
		errs = append(errs, err)
	}
	if p.DoHEnabled != nil && *p.DoHEnabled != cur.DoHEnabled {
		_, err := client.SetIsDoHEnabled(ctx, wrapperspb.Bool(*p.DoHEnabled))
		errs = append(errs, err)
	}

	b.refreshSettings(client)
	go func() {
		// The mail server change is applied asynchronously by bridge.
		time.Sleep(2 * time.Second)
		b.refreshSettings(client)
	}()

	return errors.Join(errs...)
}

// Repair asks bridge to rebuild its local cache and re-synchronise.
func (b *Bridge) Repair() error {
	client, err := b.getClient()
	if err != nil {
		return err
	}
	ctx, cancel := rpcCtx()
	defer cancel()
	_, err = client.TriggerRepair(ctx, &emptypb.Empty{})
	return err
}

// TLSCertificate returns the PEM certificate bridge presents on IMAP and SMTP,
// so mail clients can be told to trust it.
func (b *Bridge) TLSCertificate() ([]byte, error) {
	client, err := b.getClient()
	if err != nil {
		return nil, err
	}

	// Bridge can only export certificate and key together, into a directory.
	dir, err := os.MkdirTemp(b.cfg.DataDir, "cert-export-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	ctx, cancel := rpcCtx()
	defer cancel()
	if _, err := client.ExportTLSCertificates(ctx, wrapperspb.String(dir)); err != nil {
		return nil, err
	}

	// The export happens asynchronously; the key is written last.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(filepath.Join(dir, "key.pem")); err == nil {
			if cert, err := os.ReadFile(filepath.Join(dir, "cert.pem")); err == nil && len(cert) > 0 { //nolint:gosec
				return cert, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, errors.New("bridge did not export its certificate")
}
