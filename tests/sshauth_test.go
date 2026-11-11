package tests

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/whywaita/thatchbox/internal/collect"
	"github.com/whywaita/thatchbox/internal/driver"
	"github.com/whywaita/thatchbox/internal/inventory"
	"github.com/whywaita/thatchbox/internal/sshdial"
)

const (
	testPassphrase = "tb-pass-7Hq2"
	// Decrypting an OpenSSH key runs bcrypt, which is slow under -race.
	keyTimeout = 30 * time.Second
)

// clientKey returns a new key as an OpenSSH PEM (encrypted when passphrase
// is set) and its public key.
func clientKey(t *testing.T, passphrase string) ([]byte, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), signer.PublicKey()
}

func keyTarget(t *testing.T, s *sshServer, key []byte) sshdial.Target {
	t.Helper()
	tgt := target(t, s, writeKnownHosts(t, s))
	tgt.Password = ""
	tgt.PrivateKey = key
	return tgt
}

func TestSSHPrivateKeyAuth(t *testing.T) {
	key, pub := clientKey(t, "")
	srv := startSSHServer(t, sshServerOptions{user: "backup", authorizedKey: pub, device: simpleDevice()})
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
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
	_, pub := clientKey(t, "")
	other, _ := clientKey(t, "")
	srv := startSSHServer(t, sshServerOptions{user: "backup", authorizedKey: pub, device: simpleDevice()})
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	if _, err := sshdial.Open(ctx, keyTarget(t, srv, other), nil); !errors.Is(err, sshdial.ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
}

func TestSSHKeyWithPasswordFallback(t *testing.T) {
	// A server that only accepts passwords: an offered key must not prevent
	// password login.
	key, _ := clientKey(t, "")
	srv := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", device: simpleDevice()})
	tgt := keyTarget(t, srv, key)
	tgt.Password = "pw"
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	if _, err := runShowRun(t, ctx, tgt, nil); err != nil {
		t.Fatalf("password after rejected key: %v", err)
	}
}

func TestSSHKeyAndPasswordBothRequired(t *testing.T) {
	key, pub := clientKey(t, "")
	srv := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", authorizedKey: pub, requireBoth: true, device: simpleDevice()})
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
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
	key, pub := clientKey(t, testPassphrase)
	srv := startSSHServer(t, sshServerOptions{user: "backup", authorizedKey: pub, device: simpleDevice()})
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
	key, pub := clientKey(t, testPassphrase)
	srv := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", authorizedKey: pub, requireBoth: true, device: simpleDevice()})
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	h, p := hostPort(t, srv.addr)
	invPath := writeInventory(t, fmt.Sprintf(`
defaults: {known_hosts: %s}
credentials:
  lab:
    username: backup
    password: {file: %s}
    private_key: {file: %s}
    private_key_passphrase: {file: %s}
devices:
  - {name: sw1, address: %s, port: %d, driver: cisco_ios, credential: lab}
`, writeKnownHosts(t, srv), write("pw", []byte("pw\n")), write("key", key), write(testPassphrase, []byte(testPassphrase+"\n")), h, p))
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
	body := strings.Replace(validInventory, "enable_password: {file: /run/secrets/enable}",
		"private_key_passphrase: {file: /run/secrets/phrase}", 1)
	if _, err := inventory.Load(writeInventory(t, body), knownDrivers); err == nil {
		t.Fatal("passphrase without private_key accepted")
	}
}
