package sshdial_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whywaita/thatchbox/internal/collect"
	"github.com/whywaita/thatchbox/internal/driver"
	"github.com/whywaita/thatchbox/internal/inventory"
	"github.com/whywaita/thatchbox/internal/sshdial"
	"github.com/whywaita/thatchbox/internal/testutil"
)

const (
	testPassphrase = "tb-pass-7Hq2"
	// Decrypting an OpenSSH key runs bcrypt, which is slow under -race.
	keyTimeout = 30 * time.Second
)

func keyTarget(t *testing.T, s *testutil.SSHServer, key []byte) sshdial.Target {
	t.Helper()
	tgt := target(t, s, testutil.WriteKnownHosts(t, s))
	tgt.Password = ""
	tgt.PrivateKey = key
	return tgt
}

func TestSSHPrivateKeyAuth(t *testing.T) {
	key, pub := testutil.ClientKey(t, "")
	srv := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", AuthorizedKey: pub, Device: testutil.SimpleDevice()})
	ctx, cancel := context.WithTimeout(context.Background(), testutil.ShortTimeout)
	defer cancel()
	out, err := runShowRun(t, ctx, keyTarget(t, srv, key), nil)
	if err != nil {
		t.Fatalf("key auth: %v", err)
	}
	if !strings.Contains(out, "hostname example-sw") {
		t.Fatalf("unexpected output %q", out)
	}
}

func TestSSHPrivateKeyNotAuthorized(t *testing.T) {
	_, pub := testutil.ClientKey(t, "")
	other, _ := testutil.ClientKey(t, "")
	srv := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", AuthorizedKey: pub, Device: testutil.SimpleDevice()})
	ctx, cancel := context.WithTimeout(context.Background(), testutil.ShortTimeout)
	defer cancel()
	if _, err := sshdial.Open(ctx, keyTarget(t, srv, other), nil); !errors.Is(err, sshdial.ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
}

func TestSSHKeyWithPasswordFallback(t *testing.T) {
	// A server that only accepts passwords: an offered key must not prevent
	// password login.
	key, _ := testutil.ClientKey(t, "")
	srv := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", Password: "pw", Device: testutil.SimpleDevice()})
	tgt := keyTarget(t, srv, key)
	tgt.Password = "pw"
	ctx, cancel := context.WithTimeout(context.Background(), testutil.ShortTimeout)
	defer cancel()
	if _, err := runShowRun(t, ctx, tgt, nil); err != nil {
		t.Fatalf("password after rejected key: %v", err)
	}
}

func TestSSHKeyAndPasswordBothRequired(t *testing.T) {
	key, pub := testutil.ClientKey(t, "")
	srv := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", Password: "pw", AuthorizedKey: pub, RequireBoth: true, Device: testutil.SimpleDevice()})
	ctx, cancel := context.WithTimeout(context.Background(), testutil.ShortTimeout)
	defer cancel()
	tgt := keyTarget(t, srv, key)
	if _, err := sshdial.Open(ctx, tgt, nil); !errors.Is(err, sshdial.ErrAuth) {
		t.Fatalf("key alone: want ErrAuth, got %v", err)
	}
	tgt.Password = "pw"
	if _, err := runShowRun(t, ctx, tgt, nil); err != nil {
		t.Fatalf("key and password: %v", err)
	}
}

func TestSSHEncryptedPrivateKey(t *testing.T) {
	key, pub := testutil.ClientKey(t, testPassphrase)
	srv := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", AuthorizedKey: pub, Device: testutil.SimpleDevice()})
	ctx, cancel := context.WithTimeout(context.Background(), keyTimeout)
	defer cancel()
	tgt := keyTarget(t, srv, key)
	if _, err := sshdial.Open(ctx, tgt, nil); err == nil || strings.Contains(err.Error(), testPassphrase) {
		t.Fatalf("missing passphrase: %v", err)
	}
	tgt.PrivateKeyPassphrase = "wrong"
	if _, err := sshdial.Open(ctx, tgt, nil); err == nil || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("wrong passphrase: %v", err)
	}
	tgt.PrivateKeyPassphrase = testPassphrase
	if _, err := runShowRun(t, ctx, tgt, nil); err != nil {
		t.Fatalf("encrypted key: %v", err)
	}
}

// The inventory path: private_key, private_key_passphrase and password are
// read from files and used together.
func TestCollectWithKeyFromInventory(t *testing.T) {
	key, pub := testutil.ClientKey(t, testPassphrase)
	srv := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", Password: "pw", AuthorizedKey: pub, RequireBoth: true, Device: testutil.SimpleDevice()})
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	h, p := testutil.HostPort(t, srv.Addr)
	invPath := testutil.WriteInventory(t, fmt.Sprintf(`
defaults: {known_hosts: %s}
credentials:
  lab:
    username: backup
    password: {file: %s}
    private_key: {file: %s}
    private_key_passphrase: {file: %s}
devices:
  - {name: sw1, address: %s, port: %d, driver: cisco_ios, credential: lab}
`, testutil.WriteKnownHosts(t, srv), write("pw", []byte("pw\n")), write("key", key), write(testPassphrase, []byte(testPassphrase+"\n")), h, p))
	reg, err := driver.Load("")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.Load(invPath, func(n string) bool { _, ok := reg.Get(n); return ok })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), keyTimeout)
	defer cancel()
	files, err := (&collect.Collector{Inventory: inv, Drivers: reg}).Collect(ctx, inv.Devices[0])
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !strings.Contains(string(files["running-config"]), "hostname example-sw") {
		t.Fatalf("unexpected files %v", files)
	}
}

func TestInventoryRejectsPassphraseWithoutKey(t *testing.T) {
	body := strings.Replace(testutil.ValidInventory, "enable_password: {file: /run/secrets/enable}",
		"private_key_passphrase: {file: /run/secrets/phrase}", 1)
	if _, err := inventory.Load(testutil.WriteInventory(t, body), testutil.KnownDrivers); err == nil {
		t.Fatal("passphrase without private_key accepted")
	}
}
