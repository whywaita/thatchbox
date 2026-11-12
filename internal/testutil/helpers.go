// Package testutil holds the fakes shared by the tests: devices behind
// in-process SSH and telnet servers, git remotes and sample data.
package testutil

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/crypto/ssh"

	"github.com/whywaita/thatchbox/internal/driver"
	"github.com/whywaita/thatchbox/internal/store"
)

// WriteFile writes data to a new file in a temporary directory.
func WriteFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Registry loads the built-in drivers.
func Registry(t *testing.T) *driver.Registry {
	t.Helper()
	reg, err := driver.Load("")
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// ParseDriver parses a driver definition.
func ParseDriver(t *testing.T, def string) *driver.Driver {
	t.Helper()
	d, err := driver.Parse([]byte(def))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// CiscoDriver returns the built-in cisco_ios driver.
func CiscoDriver(t *testing.T) *driver.Driver {
	t.Helper()
	d, _ := Registry(t).Get("cisco_ios")
	return d
}

// CiscoRunning is a running-config with every kind of secret the cisco_ios
// driver masks.
const CiscoRunning = `Building configuration...

Current configuration : 1234 bytes
!
! Last configuration change at 12:00:00 JST Mon Nov 9 2026 by admin
! NVRAM config last updated at 12:00:01 JST Mon Nov 9 2026 by admin
!
version 15.2
hostname example-sw
!
enable secret 9 $9$abcdefghijklmnop$qrstuvwxyz0123456789
username admin privilege 15 secret 9 $9$zzzzzzzzzzzz$yyyyyyyyyyyy
!
ntp clock-period 36028797
snmp-server community s3cr3t-comm RO
crypto isakmp key psk-value address 0.0.0.0
line vty 0 4
 password 7 0822455D0A16
!
end
`

// ValidInventory exercises defaults, credentials, a jump host and a disabled
// device.
const ValidInventory = `
defaults:
  concurrency: 4
  timeout: 90s
  known_hosts: /etc/thatchbox/known_hosts
credentials:
  netadmin:
    username: backup
    password: {env: TB_TEST_PASSWORD}
    enable_password: {file: /run/secrets/enable}
  keyonly:
    username: {env: TB_TEST_USER}
    private_key: {file: /run/secrets/id_ed25519}
jump_hosts:
  bastion:
    address: bastion.example.net
    credential: keyonly
devices:
  - name: core-sw1
    address: 192.0.2.1
    driver: cisco_ios
    credential: netadmin
    ssh:
      kex: ["+diffie-hellman-group1-sha1"]
  - name: edge.r1
    address: 192.0.2.2
    port: 2222
    driver: junos
    credential: keyonly
    jump: bastion
    timeout: 5m
  - name: old-ix
    address: 192.0.2.3
    driver: nec_ix
    credential: netadmin
    enabled: false
`

// WriteInventory writes body as an inventory file and returns its path.
func WriteInventory(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// KnownDrivers reports whether name is a built-in driver.
func KnownDrivers(name string) bool {
	return name == "cisco_ios" || name == "junos" || name == "nec_ix"
}

// ShortTimeout bounds a session with the in-process fakes.
const ShortTimeout = 2 * time.Second

// ClientKey returns a new key as an OpenSSH PEM (encrypted when passphrase
// is set) and its public key.
func ClientKey(t *testing.T, passphrase string) ([]byte, ssh.PublicKey) {
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

// SimpleDevice answers "show running-config" with CiscoRunning.
func SimpleDevice() *FakeDevice {
	return &FakeDevice{Hostname: "sw1", Commands: map[string]string{"show running-config": CiscoRunning}}
}

// StoreAt clones remote into dir on branch.
func StoreAt(t *testing.T, remote, dir, branch string) *store.Repo {
	t.Helper()
	r, err := store.Clone(context.Background(), store.Options{
		URL: remote, Dir: dir, Branch: branch,
		AuthorName: "thatchbox", AuthorEmail: "thatchbox@example.invalid",
	})
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	return r
}

// RemoteWithStatus returns a remote whose main branch holds status.json
// with exactly content.
func RemoteWithStatus(t *testing.T, content string) string {
	t.Helper()
	remote := NewRemote(t)
	dir := filepath.Join(t.TempDir(), "work")
	r := StoreAt(t, remote, dir, "main")
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Commit("status"); err != nil {
		t.Fatal(err)
	}
	if err := r.Push(context.Background()); err != nil {
		t.Fatal(err)
	}
	return remote
}

// NewRemote creates an empty bare repository.
func NewRemote(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "remote.git")
	if _, err := git.PlainInit(dir, true); err != nil {
		t.Fatal(err)
	}
	return dir
}

// OpenStore clones remote on main.
func OpenStore(t *testing.T, remote string) *store.Repo {
	t.Helper()
	return OpenStoreDepth(t, remote, 0)
}

// OpenStoreDepth clones remote on main with the given depth.
func OpenStoreDepth(t *testing.T, remote string, depth int) *store.Repo {
	t.Helper()
	r, err := store.Clone(context.Background(), store.Options{
		Depth:       depth,
		URL:         remote,
		Dir:         filepath.Join(t.TempDir(), "work"),
		Branch:      "main",
		AuthorName:  "thatchbox",
		AuthorEmail: "thatchbox@example.invalid",
	})
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	return r
}

// RemoteCommits returns the commits on the remote's main branch, newest
// first.
func RemoteCommits(t *testing.T, remote string) []*object.Commit {
	t.Helper()
	repo, err := git.PlainOpen(remote)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := repo.Reference("refs/heads/main", true)
	if err != nil {
		t.Fatalf("main branch: %v", err)
	}
	iter, err := repo.Log(&git.LogOptions{From: ref.Hash()})
	if err != nil {
		t.Fatal(err)
	}
	var out []*object.Commit
	_ = iter.ForEach(func(c *object.Commit) error {
		out = append(out, c)
		return nil
	})
	return out
}
