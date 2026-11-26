package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	mbsyncBin    = "mbsync"
	syncChannel  = "sync"
	syncErrLines = 12

	// The deletion guard looks at removals over this long.
	syncGuardWindow = time.Hour
)

// Mailboxes whose content was thrown away already: emptying them is not what
// the deletion guard is about. The names are those bridge uses.
var binBoxes = map[string]bool{"Trash": true, "Spam": true}

// syncTick is how often each worker looks at Dovecot for changes made by mail
// clients. Tests shorten it.
var syncTick = 5 * time.Second

// MailAccount is one IMAP login served by bridge: an address and the bridge
// password. In combined address mode an account has one, in split mode one per
// address.
type MailAccount struct {
	Login    string
	Password string
	Ready    bool // false while bridge is still doing its own first synchronisation
}

// MailSource is the bridge side of the sync.
type MailSource interface {
	MailAccounts() []MailAccount
	IMAPEndpoint() (host string, port int, implicitTLS bool)
	TLSCertificate() ([]byte, error)
}

// SyncStatus is shown in the web UI for every login.
type SyncStatus struct {
	// State is one of: waiting, syncing, ok, paused, error.
	State    string    `json:"state"`
	Message  string    `json:"message,omitempty"`
	LastSync time.Time `json:"lastSync"`
	Messages int       `json:"messages"`
	// PendingDeletions is the number of messages that disappeared from Dovecot
	// since the last sync, when that is more than the guard allows.
	PendingDeletions int `json:"pendingDeletions,omitempty"`
}

// syncRecord is persisted next to the mail, so that losing the mail directory
// also loses the record and a fresh copy is pulled instead of deletions pushed.
type syncRecord struct {
	// Counts is the number of messages per mailbox after the last sync, not
	// counting those flagged \Deleted.
	Counts map[string]int `json:"counts"`
	// Removed lists how many removals were handed to the sync recently, for
	// the deletion guard.
	Removed  []removal `json:"removed,omitempty"`
	LastSync time.Time `json:"lastSync"`
}

type removal struct {
	At time.Time `json:"at"`
	N  int       `json:"n"`
}

// recentlyRemoved forgets removals older than the guard's window and adds up the rest.
func (r *syncRecord) recentlyRemoved(now time.Time) int {
	kept, sum := r.Removed[:0], 0
	for _, x := range r.Removed {
		if now.Sub(x.At) < syncGuardWindow {
			kept, sum = append(kept, x), sum+x.N
		}
	}
	r.Removed = kept
	return sum
}

// SyncManager keeps Dovecot and bridge in step, in both directions, with one
// worker per login. The copying itself is done by mbsync.
type SyncManager struct {
	cfg     Config
	dovecot *Dovecot
	source  MailSource

	mu       sync.Mutex
	workers  map[string]*syncWorker
	passwdID string
}

func NewSyncManager(cfg Config, dovecot *Dovecot, source MailSource) *SyncManager {
	return &SyncManager{cfg: cfg, dovecot: dovecot, source: source, workers: map[string]*syncWorker{}}
}

// validLogin rejects logins that could not be used safely as a directory name.
func validLogin(login string) bool {
	return login != "" && login != "." && login != ".." &&
		!strings.ContainsAny(login, "/\\\x00\r\n\t\"'") && !strings.HasPrefix(login, "-")
}

// Run reconciles the set of workers with the accounts bridge has, until ctx is cancelled.
func (m *SyncManager) Run(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()

	ticker := time.NewTicker(syncTick)
	defer ticker.Stop()

	for {
		m.reconcile(ctx, &wg)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *SyncManager) reconcile(ctx context.Context, wg *sync.WaitGroup) {
	accounts := m.source.MailAccounts()

	valid := accounts[:0:0]
	for _, a := range accounts {
		if validLogin(a.Login) {
			a.Login = strings.ToLower(a.Login)
			valid = append(valid, a)
		} else {
			log.Printf("sync: ignoring login %q, it cannot be used as a mailbox name", a.Login)
		}
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].Login < valid[j].Login })

	// Dovecot accepts the same credentials as bridge, so clients need only one password.
	var id strings.Builder
	for _, a := range valid {
		id.WriteString(a.Login + "\x00" + a.Password + "\x00")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if sum := sha256.Sum256([]byte(id.String())); m.passwdID != hex.EncodeToString(sum[:]) {
		if err := m.dovecot.WritePasswd(valid); err != nil {
			log.Printf("sync: cannot update Dovecot logins: %v", err)
		} else {
			m.passwdID = hex.EncodeToString(sum[:])
		}
	}

	seen := map[string]bool{}
	for _, a := range valid {
		seen[a.Login] = true
		w, ok := m.workers[a.Login]
		if !ok {
			wctx, cancel := context.WithCancel(ctx)
			w = newSyncWorker(m, a.Login, cancel)
			m.workers[a.Login] = w
			wg.Add(1)
			go func() {
				defer wg.Done()
				w.run(wctx)
			}()
		}
		w.setAccount(a)
	}
	for login, w := range m.workers {
		if !seen[login] {
			// The mail stays on disk; it is picked up again if the account returns.
			w.cancel()
			delete(m.workers, login)
		}
	}
}

// Status returns the sync status of every login.
func (m *SyncManager) Status() map[string]SyncStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]SyncStatus, len(m.workers))
	for login, w := range m.workers {
		out[login] = w.getStatus()
	}
	return out
}

func (m *SyncManager) worker(login string) (*syncWorker, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.workers[strings.ToLower(login)]
	if !ok {
		return nil, fmt.Errorf("no mailbox is being synchronised for %q", login)
	}
	return w, nil
}

// SyncNow asks for an immediate full sync of one login.
func (m *SyncManager) SyncNow(login string) error {
	w, err := m.worker(login)
	if err != nil {
		return err
	}
	w.signal(w.kick)
	return nil
}

// ApproveDeletions lets a sync that the deletion guard paused go ahead once.
func (m *SyncManager) ApproveDeletions(login string) error {
	w, err := m.worker(login)
	if err != nil {
		return err
	}
	w.signal(w.approve)
	return nil
}

// Rebuild throws away the Dovecot copy of one login and downloads it again
// from bridge. Nothing is changed on Proton; changes made in Dovecot that were
// not synchronised yet are lost.
func (m *SyncManager) Rebuild(login string) error {
	w, err := m.worker(login)
	if err != nil {
		return err
	}
	w.signal(w.rebuild)
	return nil
}

// ---------------------------------------------------------------------------
// worker
// ---------------------------------------------------------------------------

type syncWorker struct {
	m      *SyncManager
	login  string
	cancel context.CancelFunc

	home   string // Dovecot home of the login: mail, index, sync state
	dir    string // generated mbsync configuration
	rcPath string

	kick    chan struct{}
	approve chan struct{}
	rebuild chan struct{}

	mu      sync.Mutex
	account MailAccount
	status  SyncStatus
}

func newSyncWorker(m *SyncManager, login string, cancel context.CancelFunc) *syncWorker {
	sum := sha256.Sum256([]byte(login))
	dir := filepath.Join(m.cfg.DataDir, "sync", hex.EncodeToString(sum[:8]))
	return &syncWorker{
		m:       m,
		login:   login,
		cancel:  cancel,
		home:    m.dovecot.Home(login),
		dir:     dir,
		rcPath:  filepath.Join(dir, "mbsyncrc"),
		kick:    make(chan struct{}, 1),
		approve: make(chan struct{}, 1),
		rebuild: make(chan struct{}, 1),
		status:  SyncStatus{State: "waiting", Message: "Starting."},
	}
}

func (w *syncWorker) signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (w *syncWorker) setAccount(a MailAccount) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.account = a
}

func (w *syncWorker) getAccount() MailAccount {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.account
}

func (w *syncWorker) getStatus() SyncStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

func (w *syncWorker) setStatus(fn func(*SyncStatus)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fn(&w.status)
}

func (w *syncWorker) recordPath() string { return filepath.Join(w.home, "sync-record.json") }

func (w *syncWorker) loadRecord() syncRecord {
	var r syncRecord
	if data, err := os.ReadFile(w.recordPath()); err == nil {
		_ = json.Unmarshal(data, &r)
	}
	if r.Counts == nil {
		r.Counts = map[string]int{}
	}
	return r
}

func (w *syncWorker) saveRecord(r syncRecord) {
	data, err := json.Marshal(r)
	if err != nil {
		return
	}
	tmp := w.recordPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("sync %s: cannot save sync record: %v", w.login, err)
		return
	}
	_ = os.Rename(tmp, w.recordPath())
}

func mbsyncQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// writeConfig generates the mbsync configuration for this login.
func (w *syncWorker) writeConfig(a MailAccount) error {
	for _, dir := range []string{w.dir, w.home, filepath.Join(w.home, "mbsync")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	passPath := filepath.Join(w.dir, "pass")
	if err := os.WriteFile(passPath, []byte(a.Password+"\n"), 0o600); err != nil {
		return err
	}

	certPath := filepath.Join(w.dir, "bridge-cert.pem")
	cert, err := w.m.source.TLSCertificate()
	if err != nil {
		return fmt.Errorf("cannot read bridge's TLS certificate: %w", err)
	}
	if err := os.WriteFile(certPath, cert, 0o600); err != nil {
		return err
	}

	host, port, implicitTLS := w.m.source.IMAPEndpoint()
	tlsType := "STARTTLS"
	if implicitTLS {
		tlsType = "IMAPS"
	}

	patterns := []string{"*"}
	for _, x := range w.m.cfg.SyncExclude {
		patterns = append(patterns, "!"+mbsyncQuote(x))
	}

	rc := fmt.Sprintf(`# Generated by mailbridge. Changes are overwritten.

# Far side: Proton Mail Bridge.
IMAPAccount bridge
Host %s
Port %d
User %s
PassCmd "cat '%s'"
SSLType %s
CertificateFile %s
PipelineDepth 1
Timeout 120

IMAPStore far
Account bridge
# Bridge does not announce its hierarchy delimiter the way mbsync looks for it.
PathDelimiter /

# Near side: Dovecot, reached through its own IMAP process so that its indexes
# and the full-text search index always stay consistent.
IMAPAccount dovecot
Tunnel "%s -c '%s' -u '%s'"
Timeout 120

IMAPStore near
Account dovecot

Channel %s
Far :far:
Near :near:
Patterns %s
Sync All
Create Both
# Mailbox deletions are propagated, but mbsync never deletes a non-empty mailbox.
Remove Both
Expunge Both
CopyArrivalDate yes
SyncState %s/
`, host, port, mbsyncQuote(a.Login), passPath, tlsType, certPath,
		dovecotIMAP, w.m.dovecot.confPath, a.Login,
		syncChannel, strings.Join(patterns, " "), filepath.Join(w.home, "mbsync"))

	return os.WriteFile(w.rcPath, []byte(rc), 0o600)
}

// mbsync runs one sync. boxes limits it to those mailboxes; none means all.
func (w *syncWorker) mbsync(ctx context.Context, boxes []string) error {
	target := syncChannel
	if len(boxes) > 0 {
		target += ":" + strings.Join(boxes, ",")
	}

	args := []string{"-c", w.rcPath, target}
	if w.m.cfg.SyncDebug {
		args = append([]string{"-V"}, args...)
	}
	cmd := exec.CommandContext(ctx, mbsyncBin, args...) // #nosec G204
	// Let mbsync finish the message it is on and write its journal when we stop.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 15 * time.Second
	cmd.Env = append(os.Environ(), "LC_ALL=C.UTF-8")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if w.m.cfg.SyncDebug {
		log.Printf("sync %s: mbsync %s:\n%s", w.login, target, strings.TrimSpace(out.String()))
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Keep what mbsync complained about for the web UI. It can exit with
	// success after skipping a mailbox with only a warning, so look at the
	// output either way.
	var lines []string
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		complaint := strings.Contains(line, "Warning:") || strings.Contains(line, "rror:") || strings.Contains(line, "returned an error")
		if line == "" || (!complaint && (err == nil || w.m.cfg.SyncDebug)) {
			continue
		}
		if strings.HasPrefix(line, "C:") || strings.HasPrefix(line, "B:") || strings.HasPrefix(line, "F:") || strings.HasPrefix(line, "N:") {
			continue // progress counters
		}
		if strings.HasPrefix(line, "imap(") && strings.Contains(line, ": Info: ") {
			continue // Dovecot's side of the tunnel logging its session
		}
		lines = append(lines, line)
	}
	if len(lines) > syncErrLines {
		lines = lines[len(lines)-syncErrLines:]
	}
	switch {
	case len(lines) > 0:
		// mbsync calls bridge the far side and Dovecot the near side.
		text := strings.NewReplacer("far side", "Proton side", "near side", "Dovecot side").Replace(strings.Join(lines, "\n"))
		return fmt.Errorf("%s", text)
	case err != nil:
		return fmt.Errorf("mbsync failed: %v", err)
	}
	return nil
}

// kept is the number of messages per mailbox, without those flagged \Deleted:
// the next sync expunges them, so they are as good as gone.
func kept(boxes map[string]boxStatus, flagged map[string]int) map[string]int {
	out := make(map[string]int, len(boxes))
	for name, b := range boxes {
		out[name] = max(b.Messages-flagged[name], 0)
	}
	return out
}

// dropped is the number of messages that were in Dovecot after the last sync
// and have left it since, which is what a sync would remove from Proton.
// Moving mail between folders does not count, and neither does moving it to
// Trash or Spam or emptying those: only mail that leaves the other folders
// without arriving anywhere does.
func dropped(before, now map[string]int) int {
	var hadKept, hadBin, nowKept, nowBin int
	for name, n := range before {
		if binBoxes[name] {
			hadBin += n
		} else {
			hadKept += n
		}
	}
	for name, n := range now {
		if binBoxes[name] {
			nowBin += n
		} else {
			nowKept += n
		}
	}
	return max((hadKept-nowKept)-max(nowBin-hadBin, 0), 0)
}

func total(boxes map[string]boxStatus) int {
	n := 0
	for _, b := range boxes {
		n += b.Messages
	}
	return n
}

// signature changes whenever anything in any of the mailboxes changes.
func signature(boxes map[string]boxStatus) string {
	names := make([]string, 0, len(boxes))
	for name := range boxes {
		names = append(names, name)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, name := range names {
		sb.WriteString(name + "\x00" + boxes[name].Sig + "\x00")
	}
	return sb.String()
}

// wipe removes the Dovecot copy of this login: mail, indexes and sync state.
func (w *syncWorker) wipe(ctx context.Context) error {
	w.m.dovecot.Kick(ctx, w.login)
	if err := os.RemoveAll(w.home); err != nil {
		return err
	}
	// A mail client may have reconnected and recreated part of it meanwhile.
	w.m.dovecot.Kick(ctx, w.login)
	return os.RemoveAll(w.home)
}

// excluded reports whether a mailbox is left out of the sync. The patterns use
// the IMAP wildcards: "*" matches anything, "%" anything within one level.
func (w *syncWorker) excluded(box string) bool {
	for _, pattern := range w.m.cfg.SyncExclude {
		if wildcardMatch(pattern, box) {
			return true
		}
	}
	return false
}

func wildcardMatch(pattern, name string) bool {
	if pattern == "" {
		return name == ""
	}
	switch pattern[0] {
	case '*', '%':
		for i := 0; i <= len(name); i++ {
			if wildcardMatch(pattern[1:], name[i:]) {
				return true
			}
			if i < len(name) && pattern[0] == '%' && name[i] == '/' {
				break
			}
		}
		return false
	default:
		return name != "" && pattern[0] == name[0] && wildcardMatch(pattern[1:], name[1:])
	}
}

// plan decides what the next mbsync run covers: everything (full), a list of
// mailboxes, or nothing.
func (w *syncWorker) plan(boxes map[string]boxStatus, sigs map[string]string, forced bool, lastFull, lastFast time.Time) (targets []string, full, fast bool) {
	if forced || time.Since(lastFull) >= w.m.cfg.SyncFullInterval {
		return nil, true, true
	}
	for box := range sigs {
		if _, ok := boxes[box]; !ok {
			return nil, true, true // a mailbox was deleted or renamed in Dovecot
		}
	}

	want := map[string]bool{}
	for box, b := range boxes {
		if sigs[box] != b.Sig && !w.excluded(box) {
			want[box] = true // changed by a mail client
		}
	}
	if fast = time.Since(lastFast) >= w.m.cfg.SyncFastInterval; fast {
		for _, box := range w.m.cfg.SyncFastBoxes {
			if _, ok := boxes[box]; (ok || box == "INBOX") && !w.excluded(box) {
				want[box] = true
			}
		}
	}

	for box := range want {
		if strings.Contains(box, ",") {
			return nil, true, true // cannot be named on mbsync's command line
		}
		targets = append(targets, box)
	}
	sort.Strings(targets)
	return targets, false, fast
}

func (w *syncWorker) run(ctx context.Context) {
	log.Printf("sync %s: started", w.login)
	defer log.Printf("sync %s: stopped", w.login)

	var (
		record     = w.loadRecord()
		sigs       = map[string]string{} // Dovecot right after our last sync, per mailbox
		observed   string                // state of Dovecot for which flagged was counted
		flagged    map[string]int        // messages flagged \Deleted in Dovecot, per mailbox
		lastFull   time.Time
		lastFast   time.Time
		configured MailAccount
		approved   bool
		forced     = true // always start with a full sync
		failures   int
		retryAt    time.Time
		problem    string // what a sync complained about, shown until a sync of the same reach succeeds
		wideIssue  bool   // whether that sync covered more than the often-checked folders
	)
	w.setStatus(func(s *SyncStatus) { s.LastSync = record.LastSync })

	fail := func(err error) {
		w.setStatus(func(s *SyncStatus) { s.State, s.Message = "error", err.Error() })
	}

	// look reads the state of Dovecot: mailboxes and messages flagged as deleted.
	look := func() (map[string]boxStatus, error) {
		boxes, err := w.m.dovecot.Status(ctx, w.login)
		if err != nil {
			return nil, err
		}
		if sig := signature(boxes); sig != observed || flagged == nil {
			if flagged, err = w.m.dovecot.Flagged(ctx, w.login); err != nil {
				return nil, err
			}
			observed = sig
		}
		return boxes, nil
	}

	ticker := time.NewTicker(syncTick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.kick:
			forced = true
		case <-w.approve:
			approved, forced = true, true
		case <-w.rebuild:
			log.Printf("sync %s: rebuilding the Dovecot copy from bridge", w.login)
			w.setStatus(func(s *SyncStatus) { *s = SyncStatus{State: "syncing", Message: "Removing the Dovecot copy."} })
			if err := w.wipe(ctx); err != nil {
				fail(fmt.Errorf("cannot remove the Dovecot copy: %w", err))
				continue
			}
			record = syncRecord{Counts: map[string]int{}}
			sigs, observed, flagged = map[string]string{}, "", nil
			lastFull, lastFast, configured = time.Time{}, time.Time{}, MailAccount{}
			approved, forced, failures, retryAt, problem, wideIssue = false, true, 0, time.Time{}, "", false
		case <-ticker.C:
		}

		if !forced && time.Now().Before(retryAt) {
			continue
		}

		acct := w.getAccount()
		if !acct.Ready {
			w.setStatus(func(s *SyncStatus) {
				s.State, s.Message = "waiting", "Waiting for bridge to finish its own synchronisation with Proton."
			})
			continue
		}

		if acct != configured || forced {
			if err := w.writeConfig(acct); err != nil {
				fail(err)
				continue
			}
			configured = acct
		}

		boxes, err := look()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fail(err)
			continue
		}

		// The guard: a sync removes from Proton whatever was removed in Dovecot.
		// Some of that is normal use; a lot of it in a short time may be a mail
		// client gone wrong or a damaged volume, so a person has to confirm.
		gone := dropped(record.Counts, kept(boxes, flagged))
		if recent := record.recentlyRemoved(time.Now()); gone > 0 && gone+recent > w.m.cfg.SyncMaxDelete && !approved {
			if w.getStatus().State != "paused" {
				log.Printf("sync %s: paused, %d messages were removed in Dovecot since the last sync (%d more in the hour before)",
					w.login, gone, recent)
			}
			w.setStatus(func(s *SyncStatus) {
				s.State, s.PendingDeletions, s.Messages = "paused", gone, total(boxes)
				s.Message = fmt.Sprintf("%d messages were removed from this mailbox since the last sync", gone)
				if recent > 0 {
					s.Message += fmt.Sprintf(", after %d in the hour before", recent)
				}
				s.Message += ". Sync is paused so that they are not removed from Proton by mistake."
			})
			forced = false
			continue
		}

		targets, full, fast := w.plan(boxes, sigs, forced, lastFull, lastFast)
		if !full && len(targets) == 0 {
			if st := w.getStatus(); st.State == "paused" || st.State == "waiting" {
				w.setStatus(func(s *SyncStatus) { s.State, s.Message, s.PendingDeletions = "ok", "", 0 })
			}
			continue
		}

		// Routine background runs do not flicker the status; the first copy
		// and anything a person asked for are shown as in progress.
		w.setStatus(func(s *SyncStatus) {
			switch {
			case s.LastSync.IsZero():
				s.State = "syncing"
				s.Message = "Copying the mailbox into Dovecot for the first time. This can take hours for a large mailbox."
			case forced || s.State == "waiting" || s.State == "paused":
				s.State, s.Message = "syncing", ""
			}
			s.PendingDeletions = 0
		})

		started := time.Now()
		syncErr := w.mbsync(ctx, targets)
		if ctx.Err() != nil {
			return
		}

		now := time.Now()
		if fast {
			lastFast = now
		}
		if full {
			lastFull = now
			forced = false
		}

		// The removals seen above are with mbsync now. Remember them for the
		// guard, unless a person just approved them.
		if approved {
			record.Removed, approved = nil, false
		} else if gone > 0 {
			record.Removed = append(record.Removed, removal{At: now, N: gone})
		}

		// Whatever happened, the sync has seen the current state of Dovecot:
		// remember it so that the same change does not trigger again.
		if after, err := look(); err == nil {
			counts := kept(after, flagged)
			if full {
				// Mail clients that only show subscribed folders need new
				// folders subscribed; later unsubscribing in a client sticks.
				var fresh []string
				for name := range after {
					if _, known := record.Counts[name]; !known {
						fresh = append(fresh, name)
					}
				}
				if len(fresh) > 0 {
					sort.Strings(fresh)
					if err := w.m.dovecot.Subscribe(ctx, w.login, fresh); err != nil {
						log.Printf("sync %s: %v", w.login, err)
					}
				}

				sigs, record.Counts = map[string]string{}, counts
				for name, b := range after {
					sigs[name] = b.Sig
				}
			} else {
				for name, b := range after {
					if _, known := sigs[name]; !known || w.excluded(name) || contains(targets, name) {
						sigs[name], record.Counts[name] = b.Sig, counts[name]
					}
				}
			}
			boxes = after
		}

		// A sync of only the folders that are checked often says little about
		// the rest: it neither clears nor replaces what an earlier sync reported.
		wide := full || !subset(targets, w.m.cfg.SyncFastBoxes)
		if syncErr != nil {
			// Retry with a growing pause, and regenerate the configuration in
			// case bridge's port, TLS mode or certificate changed.
			failures++
			retryAt = now.Add(min(w.m.cfg.SyncFastInterval<<min(failures, 6), 5*time.Minute))
			configured = MailAccount{}
			if msg := syncErr.Error(); msg != problem {
				log.Printf("sync %s: mbsync reported problems:\n%s", w.login, msg)
				problem = msg
			}
			wideIssue = wideIssue || wide
		} else {
			failures, retryAt = 0, time.Time{}
			record.LastSync = now
			if wide || !wideIssue {
				problem, wideIssue = "", false
			}
		}
		w.saveRecord(record)

		w.setStatus(func(s *SyncStatus) {
			s.State, s.Message, s.LastSync, s.Messages = "ok", "", record.LastSync, total(boxes)
			if problem != "" {
				s.State, s.Message = "error", problem
				if strings.Contains(problem, "UIDVALIDITY") {
					s.Message += "\nBridge has rebuilt its copy of the mailbox, so the Dovecot copy no longer lines up with it. " +
						"Use \"Rebuild from Proton\" to download it again."
				}
			}
		})
		if full && syncErr == nil && now.Sub(started) > 30*time.Second {
			log.Printf("sync %s: full sync finished in %s", w.login, now.Sub(started).Round(time.Second))
		}
	}
}

func subset(list, of []string) bool {
	for _, x := range list {
		if !contains(of, x) {
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
