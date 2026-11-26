package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWildcardMatch(t *testing.T) {
	for _, c := range []struct {
		pattern, name string
		want          bool
	}{
		{"All Mail", "All Mail", true},
		{"All Mail", "All Mail/x", false},
		{"All Mail", "all mail", false},
		{"Labels/*", "Labels/a/b", true},
		{"Labels/%", "Labels/a", true},
		{"Labels/%", "Labels/a/b", false},
		{"*", "", true},
		{"*Mail", "All Mail", true},
		{"", "x", false},
	} {
		if got := wildcardMatch(c.pattern, c.name); got != c.want {
			t.Errorf("wildcardMatch(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestDropped(t *testing.T) {
	before := map[string]int{"INBOX": 100, "Archive": 50, "Trash": 30}
	for _, c := range []struct {
		name string
		now  map[string]int
		want int
	}{
		{"nothing changed", map[string]int{"INBOX": 100, "Archive": 50, "Trash": 30}, 0},
		{"moved between folders", map[string]int{"INBOX": 40, "Archive": 110, "Trash": 30}, 0},
		{"new mail", map[string]int{"INBOX": 120, "Archive": 50, "Trash": 30}, 0},
		{"moved to trash", map[string]int{"INBOX": 60, "Archive": 50, "Trash": 70}, 0},
		{"trash emptied", map[string]int{"INBOX": 100, "Archive": 50, "Trash": 0}, 0},
		{"expunged", map[string]int{"INBOX": 70, "Archive": 50, "Trash": 30}, 30},
		{"some binned, some expunged", map[string]int{"INBOX": 60, "Archive": 50, "Trash": 40}, 30},
		{"folder deleted", map[string]int{"INBOX": 100, "Trash": 30}, 50},
		{"mail directory lost", map[string]int{}, 150},
	} {
		if got := dropped(before, c.now); got != c.want {
			t.Errorf("%s: dropped = %d, want %d", c.name, got, c.want)
		}
	}
	if got := dropped(nil, map[string]int{"INBOX": 0}); got != 0 {
		t.Errorf("first sync: dropped = %d, want 0", got)
	}

	flagged := kept(map[string]boxStatus{"INBOX": {Messages: 100}, "Archive": {Messages: 50}, "Trash": {Messages: 30}},
		map[string]int{"INBOX": 25})
	if got := dropped(before, flagged); got != 25 {
		t.Errorf("flagged deleted but not expunged: dropped = %d, want 25", got)
	}
}

func TestRecentlyRemoved(t *testing.T) {
	now := time.Now()
	r := syncRecord{Removed: []removal{{now.Add(-2 * time.Hour), 40}, {now.Add(-30 * time.Minute), 7}, {now.Add(-time.Minute), 5}}}
	if got := r.recentlyRemoved(now); got != 12 || len(r.Removed) != 2 {
		t.Errorf("recentlyRemoved = %d with %d entries kept, want 12 with 2", got, len(r.Removed))
	}
}

func TestValidLogin(t *testing.T) {
	for login, want := range map[string]bool{
		"jane@example.com": true, "": false, "..": false, "a/b@example.com": false,
		"-u@example.com": false, "a'b@example.com": false, "a\nb": false,
	} {
		if got := validLogin(login); got != want {
			t.Errorf("validLogin(%q) = %v, want %v", login, got, want)
		}
	}
}

func TestProxyLine(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	go func() {
		if c, err := net.Dial("tcp", ln.Addr().String()); err == nil {
			defer c.Close()
			time.Sleep(time.Second)
		}
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	want := fmt.Sprintf("PROXY TCP4 127.0.0.1 127.0.0.1 %d %d\r\n",
		conn.RemoteAddr().(*net.TCPAddr).Port, ln.Addr().(*net.TCPAddr).Port)
	if got := proxyLine(conn); got != want {
		t.Errorf("proxyLine = %q, want %q", got, want)
	}
}

// farServer stands in for Proton Mail Bridge in the integration test.
type farServer struct {
	host       string
	port       int
	user, pass string
	cert       []byte
}

func (f *farServer) MailAccounts() []MailAccount {
	return []MailAccount{{Login: f.user, Password: f.pass, Ready: true}}
}
func (f *farServer) IMAPEndpoint() (string, int, bool) { return f.host, f.port, false }
func (f *farServer) TLSCertificate() ([]byte, error)   { return f.cert, nil }
func (f *farServer) addr() string                      { return net.JoinHostPort(f.host, strconv.Itoa(f.port)) }

// startFarDovecot runs a second, plain Dovecot as the far side.
func startFarDovecot(t *testing.T, ctx context.Context, wg *sync.WaitGroup, dir string) *farServer {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(me.Gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath, err := ensureSelfSigned(Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}

	conf := fmt.Sprintf(`protocols = imap
listen = 127.0.0.1
base_dir = %[1]s/run
state_dir = %[1]s/state
instance_name = far
default_internal_user = %[2]s
default_internal_group = %[3]s
default_login_user = %[2]s
log_path = %[1]s/log
ssl = yes
ssl_cert = <%[4]s
ssl_key = <%[5]s
disable_plaintext_auth = no
first_valid_uid = %[6]s
last_valid_uid = %[6]s
first_valid_gid = %[7]s
last_valid_gid = %[7]s
mail_location = maildir:~/Maildir:LAYOUT=fs
passdb {
  driver = static
  args = password=far-password
}
userdb {
  driver = static
  args = uid=%[6]s gid=%[7]s home=%[1]s/mail/%%u
}
namespace inbox {
  inbox = yes
  separator = /
}
service imap-login {
  chroot =
  inet_listener imap {
    address = 127.0.0.1
    port = 3143
  }
  inet_listener imaps {
    port = 0
  }
}
service anvil {
  chroot =
}
service auth {
  user = $default_internal_user
}
service auth-worker {
  user = $default_internal_user
}
`, dir, me.Username, group.Name, certPath, keyPath, me.Uid, me.Gid)
	confPath := filepath.Join(dir, "dovecot.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.CommandContext(ctx, dovecotBin, "-F", "-c", confPath)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = cmd.Wait()
	}()
	t.Cleanup(func() {
		if t.Failed() {
			if log, err := os.ReadFile(filepath.Join(dir, "log")); err == nil {
				t.Logf("far Dovecot log:\n%s", log)
			}
		}
	})
	return &farServer{host: "127.0.0.1", port: 3143, user: "jane@example.com", pass: "far-password", cert: cert}
}

// TestSyncIntegration runs the real Dovecot, the real mbsync and the sync
// manager against a stand-in for bridge. By default that is a second Dovecot;
// set MAILBRIDGE_TEST_FAR_ADDR, _USER, _PASS and _CERT to use another IMAP
// server with STARTTLS, such as Gluon, the IMAP engine inside bridge.
func TestSyncIntegration(t *testing.T) {
	for _, bin := range []string{dovecotBin, doveadmBin, mbsyncBin, dovecotIMAP} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s is not installed", bin)
		}
	}
	if os.Getuid() == 0 {
		t.Skip("Dovecot does not serve mail as root")
	}

	// Short paths: Dovecot's sockets live below them.
	work, err := os.MkdirTemp("", "mbt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	var far *farServer
	if addr := os.Getenv("MAILBRIDGE_TEST_FAR_ADDR"); addr != "" {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := os.ReadFile(os.Getenv("MAILBRIDGE_TEST_FAR_CERT"))
		if err != nil {
			t.Fatal(err)
		}
		far = &farServer{host: host, user: os.Getenv("MAILBRIDGE_TEST_FAR_USER"), pass: os.Getenv("MAILBRIDGE_TEST_FAR_PASS"), cert: cert}
		far.port, _ = strconv.Atoi(port)
	} else {
		far = startFarDovecot(t, ctx, &wg, filepath.Join(work, "far"))
	}
	login := far.user

	oldTick := syncTick
	syncTick = 200 * time.Millisecond
	t.Cleanup(func() { syncTick = oldTick })

	cfg := Config{
		DataDir:          filepath.Join(work, "data"),
		MailDir:          filepath.Join(work, "mail"),
		SyncFastInterval: time.Second,
		SyncFullInterval: time.Hour, // full syncs only when the test asks, to tell the paths apart
		SyncFastBoxes:    []string{"INBOX", "Sent"},
		SyncMaxDelete:    3,
		SyncExclude:      []string{"All Mail", "Starred"},
		SyncDebug:        os.Getenv("MAILBRIDGE_SYNC_DEBUG") != "",
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	waitPort := func(addr string) {
		t.Helper()
		for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(100 * time.Millisecond) {
			if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
				_ = c.Close()
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("nothing is listening on %s", addr)
			}
		}
	}

	// --- seed the far side ----------------------------------------------------
	waitPort(far.addr())
	const nearAddr = "127.0.0.1:12143"
	farClient := func() *imapClient { return dialIMAP(t, "far", far.addr(), far.user, far.pass) }
	nearClient := func() *imapClient { return dialIMAP(t, "near", nearAddr, login, far.pass) }
	count := func(dial func() *imapClient, box string) int {
		c := dial()
		defer c.conn.Close()
		return c.count(box)
	}

	seed := farClient()
	for _, box := range []string{"Folders/Work", "All Mail"} {
		if _, err := seed.try("CREATE %s", quote(box)); err != nil {
			t.Logf("far side: %v", err)
		}
	}
	for i := 1; i <= 8; i++ {
		seed.add("INBOX", message(i, fmt.Sprintf("Inbox message %d", i), "plain text body"))
	}
	encoded := base64.StdEncoding.EncodeToString([]byte("The orchestra needs a new xylophone before the concert.\r\n"))
	seed.add("INBOX", strings.Replace(message(9, "Encoded body", encoded),
		"Content-Type: text/plain; charset=utf-8\n", "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: base64\n", 1))
	for i := 1; i <= 5; i++ {
		seed.add("Folders/Work", message(20+i, fmt.Sprintf("Work message %d", i), "plain text body"))
	}
	hasAllMail := seed.count("All Mail") >= 0
	if hasAllMail {
		seed.add("All Mail", message(40, "Only in All Mail", "plain text body"))
	}
	farInbox, farWork := 9, 5

	// --- start Dovecot mode -----------------------------------------------------
	certs, err := NewCertStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dovecot := NewDovecot(cfg, certs)
	if err := dovecot.Prepare(); err != nil {
		t.Fatal(err)
	}
	mgr := NewSyncManager(cfg, dovecot, far)
	wg.Add(2)
	go func() {
		defer wg.Done()
		dovecot.Run(ctx)
	}()
	go func() {
		defer wg.Done()
		mgr.Run(ctx)
	}()
	startForwarder(ctx, &wg, "IMAP", nearAddr, func() string { return dovecotIMAPAddr }, true)

	status := func() SyncStatus { return mgr.Status()[login] }
	eventually := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(150 * time.Millisecond) {
			if cond() {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for: %s (sync status: %+v)", what, status())
			}
		}
	}
	never := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(150 * time.Millisecond) {
			if cond() {
				t.Fatalf("must not happen: %s (sync status: %+v)", what, status())
			}
		}
	}
	inSync := func() bool { return status().State == "ok" }

	// --- first copy ----------------------------------------------------------------
	eventually("first sync", func() bool { return inSync() && !status().LastSync.IsZero() })
	waitPort(dovecotIMAPAddr)
	if n := count(nearClient, "INBOX"); n != farInbox {
		t.Fatalf("near INBOX has %d messages after the first sync, want %d", n, farInbox)
	}
	if n := count(nearClient, "Folders/Work"); n != farWork {
		t.Fatalf("near Folders/Work has %d messages after the first sync, want %d", n, farWork)
	}
	if n := count(nearClient, "All Mail"); n != -1 {
		t.Fatalf("All Mail must not be copied, but has %d messages in Dovecot", n)
	}
	if got := status().Messages; got != farInbox+farWork {
		t.Errorf("status reports %d messages, want %d", got, farInbox+farWork)
	}
	if subscribed := nearClient().mailboxes("LSUB"); !contains(subscribed, "Folders/Work") || !contains(subscribed, "INBOX") {
		t.Errorf("new folders must be subscribed, LSUB gives %q", subscribed)
	}

	// --- full-text search, on decoded text ---------------------------------------
	if hits := nearClient().search("INBOX", "BODY xylophone"); len(hits) != 1 {
		t.Errorf("body search for a word in a base64 message found %q, want one message", hits)
	}
	eventually("search index on disk", func() bool {
		found, _ := filepath.Glob(filepath.Join(dovecot.Home(login), "index", "xapian-indexes"))
		return len(found) == 1
	})
	if stray, _ := filepath.Glob(filepath.Join(dovecot.Home(login), "Maildir", "xapian-indexes")); len(stray) != 0 {
		t.Errorf("the search index must not show up as a mailbox: %q", stray)
	}

	// --- Proton to Dovecot ---------------------------------------------------------
	farClient().add("INBOX", message(50, "New in inbox", "arrived on the far side"))
	farInbox++
	eventually("new INBOX mail to arrive without a full sync", func() bool { return count(nearClient, "INBOX") == farInbox })

	farClient().add("Folders/Work", message(51, "New in folder", "arrived on the far side"))
	farWork++
	if err := mgr.SyncNow(login); err != nil {
		t.Fatal(err)
	}
	eventually("new folder mail to arrive after Sync now", func() bool { return count(nearClient, "Folders/Work") == farWork })

	// --- Dovecot to Proton ---------------------------------------------------------
	c := nearClient()
	c.cmd("SELECT INBOX")
	c.cmd(`STORE 1 +FLAGS (\Seen)`)
	eventually("read flag to reach the far side", func() bool { return len(farClient().search("INBOX", "SEEN")) == 1 })

	c.cmd(`STORE 2:3 +FLAGS (\Deleted)`)
	c.cmd("EXPUNGE")
	farInbox -= 2
	eventually("two deletions to reach the far side", func() bool { return count(farClient, "INBOX") == farInbox })

	if _, err := c.try("MOVE 2 %s", quote("Folders/Work")); err != nil {
		t.Fatal(err)
	}
	farInbox, farWork = farInbox-1, farWork+1
	eventually("a move to reach the far side", func() bool {
		return count(farClient, "INBOX") == farInbox && count(farClient, "Folders/Work") == farWork
	})

	c.cmd("CREATE %s", quote("Folders/New"))
	c.add("Folders/New", message(60, "Filed by the mail client", "created in Dovecot"))
	eventually("a new folder to reach the far side", func() bool { return count(farClient, "Folders/New") == 1 })
	eventually("sync to settle", inSync)

	// --- the deletion guard, expunged messages -------------------------------------
	c.cmd("SELECT %s", quote("Folders/Work"))
	c.cmd(`STORE 1:5 +FLAGS (\Deleted)`)
	c.cmd("EXPUNGE")
	eventually("sync to pause on a large deletion", func() bool { return status().State == "paused" })
	if got := status().PendingDeletions; got != 5 {
		t.Errorf("paused with %d pending deletions, want 5", got)
	}
	if err := mgr.SyncNow(login); err != nil {
		t.Fatal(err)
	}
	never("deletions reach the far side while paused", func() bool {
		return count(farClient, "Folders/Work") != farWork || status().State != "paused"
	})
	if err := mgr.ApproveDeletions(login); err != nil {
		t.Fatal(err)
	}
	farWork -= 5
	eventually("approved deletions to reach the far side", func() bool {
		return count(farClient, "Folders/Work") == farWork && inSync()
	})

	// --- the guard adds up removals over time, and counts messages that are only
	// flagged as deleted; then rebuild ---------------------------------------------
	c.cmd("SELECT INBOX")
	c.cmd(`STORE 1:2 +FLAGS (\Deleted)`)
	c.cmd("EXPUNGE")
	farInbox -= 2
	eventually("two more deletions to reach the far side", func() bool { return count(farClient, "INBOX") == farInbox && inSync() })

	c.cmd(`STORE 1:2 +FLAGS (\Deleted)`)
	eventually("sync to pause when removals add up", func() bool { return status().State == "paused" })
	if got := status().PendingDeletions; got != 2 {
		t.Errorf("paused with %d pending deletions, want 2", got)
	}
	never("flagged messages are removed on the far side while paused", func() bool { return count(farClient, "INBOX") != farInbox })

	if err := mgr.Rebuild(login); err != nil {
		t.Fatal(err)
	}
	eventually("rebuild to finish", func() bool {
		return inSync() && count(nearClient, "INBOX") == farInbox && count(nearClient, "Folders/Work") == farWork &&
			len(nearClient().search("INBOX", "DELETED")) == 0
	})
	if n := count(farClient, "INBOX"); n != farInbox {
		t.Errorf("rebuild changed the far side: INBOX has %d messages, want %d", n, farInbox)
	}
	if n := count(nearClient, "Folders/New"); n != 1 {
		t.Errorf("after the rebuild Folders/New has %d messages in Dovecot, want 1", n)
	}

	if os.Getenv("MAILBRIDGE_TEST_FAR_ADDR") != "" {
		return
	}

	// --- bridge rebuilt its own copy ("Repair"): same mail, new numbering ----------
	// Nothing may be deleted or duplicated on either side; the page has to say
	// what to do, and a rebuild has to fix it.
	if err := os.RemoveAll(filepath.Join(work, "far", "mail")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // Dovecot numbers a new mailbox by the clock
	reseed := farClient()
	for i := 1; i <= 3; i++ {
		reseed.add("INBOX", message(70+i, fmt.Sprintf("After repair %d", i), "plain text body"))
	}
	if err := mgr.SyncNow(login); err != nil {
		t.Fatal(err)
	}
	eventually("the page to report that the two sides no longer line up", func() bool {
		st := status()
		return st.State == "error" && strings.Contains(st.Message, "Rebuild from Proton")
	})
	if n := count(farClient, "INBOX"); n != 3 {
		t.Errorf("far INBOX has %d messages after the mismatch, want 3 (nothing pushed, nothing deleted)", n)
	}
	if n := count(nearClient, "INBOX"); n != farInbox {
		t.Errorf("near INBOX has %d messages after the mismatch, want %d (untouched)", n, farInbox)
	}
	if err := mgr.Rebuild(login); err != nil {
		t.Fatal(err)
	}
	eventually("rebuild after the mismatch", func() bool {
		return inSync() && count(nearClient, "INBOX") == 3 && count(nearClient, "Folders/Work") == -1
	})
	if n := count(farClient, "INBOX"); n != 3 {
		t.Errorf("far INBOX has %d messages after the rebuild, want 3", n)
	}
}
