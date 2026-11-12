package inventory_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/whywaita/thatchbox/internal/inventory"
	"github.com/whywaita/thatchbox/internal/testutil"
)

func TestInventoryEmptyUsesBuiltinDefaults(t *testing.T) {
	inv, err := inventory.Load(testutil.WriteInventory(t, "devices: []\n"), testutil.KnownDrivers)
	if err != nil {
		t.Fatal(err)
	}
	d := inv.Defaults
	if d.Concurrency != inventory.DefaultConcurrency || d.Port != inventory.DefaultPort ||
		time.Duration(d.Timeout) != inventory.DefaultTimeout || d.MinSizeRatio != inventory.DefaultMinSizeRatio {
		t.Fatalf("defaults = %+v", d)
	}
}

// Jump hosts and devices inherit port, known_hosts and SSH algorithms from
// defaults; their own values win.
func TestInventoryInheritance(t *testing.T) {
	body := `
defaults:
  port: 2200
  known_hosts: /k/default
  min_size_ratio: 0.25
  ssh: {kex: ["+diffie-hellman-group1-sha1"], ciphers: ["+aes128-cbc"]}
credentials:
  c: {username: u, password: {env: X}}
jump_hosts:
  inherit: {address: j1, credential: c}
  own: {address: j2, credential: c, port: 22, known_hosts: /k/own, ssh: {kex: [curve25519-sha256]}}
devices:
  - {name: a, address: a, driver: junos, credential: c}
  - {name: b, address: b, driver: junos, credential: c, port: 22, known_hosts: /k/b, min_size_ratio: 0, ssh: {ciphers: [aes256-ctr]}}
`
	inv, err := inventory.Load(testutil.WriteInventory(t, body), testutil.KnownDrivers)
	if err != nil {
		t.Fatal(err)
	}
	j := inv.JumpHosts["inherit"]
	if j.Port != 2200 || j.KnownHosts != "/k/default" || !slices.Equal(j.SSH.KeyExchanges, []string{"+diffie-hellman-group1-sha1"}) {
		t.Errorf("jump host inherit = %+v", j)
	}
	j = inv.JumpHosts["own"]
	if j.Port != 22 || j.KnownHosts != "/k/own" || !slices.Equal(j.SSH.KeyExchanges, []string{"curve25519-sha256"}) ||
		!slices.Equal(j.SSH.Ciphers, []string{"+aes128-cbc"}) {
		t.Errorf("jump host own = %+v", j)
	}
	a, b := inv.Devices[0], inv.Devices[1]
	if a.Port != 2200 || a.KnownHosts != "/k/default" || *a.MinSizeRatio != 0.25 {
		t.Errorf("device a = %+v", a)
	}
	if b.Port != 22 || b.KnownHosts != "/k/b" || *b.MinSizeRatio != 0 ||
		!slices.Equal(b.SSH.Ciphers, []string{"aes256-ctr"}) || !slices.Equal(b.SSH.KeyExchanges, []string{"+diffie-hellman-group1-sha1"}) {
		t.Errorf("device b = %+v", b)
	}
}

func TestInventoryRejectsMore(t *testing.T) {
	const creds = "credentials:\n  c: {username: u, password: {env: X}}\n"
	cases := map[string]string{
		"concurrency":             "defaults: {concurrency: -1}\n" + creds,
		"defaults ratio":          "defaults: {min_size_ratio: 1.5, known_hosts: /k}\n" + creds,
		"device ratio":            "defaults: {known_hosts: /k}\n" + creds + "devices: [{name: a, address: a, driver: junos, credential: c, min_size_ratio: -0.1}]\n",
		"no secret":               "credentials:\n  c: {username: u}\n",
		"passphrase literal":      "credentials:\n  c: {username: u, private_key: {file: /k}, private_key_passphrase: pp}\n",
		"jump without address":    creds + "jump_hosts:\n  j: {credential: c, known_hosts: /k}\n",
		"jump unknown cred":       creds + "jump_hosts:\n  j: {address: j, credential: nope, known_hosts: /k}\n",
		"jump without kh":         creds + "jump_hosts:\n  j: {address: j, credential: c}\n",
		"duration not string":     "defaults: {timeout: [1]}\n",
		"secret wrong type":       "credentials:\n  c: {username: u, password: [x]}\n",
		"trailing garbage":        "devices: [\n",
		"enable_password literal": "credentials:\n  c: {username: u, password: {env: X}, enable_password: en}\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := inventory.Load(testutil.WriteInventory(t, body), testutil.KnownDrivers); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestInventoryReportsAllErrors(t *testing.T) {
	body := "credentials:\n  c: {username: u, password: {env: X}}\ndevices:\n" +
		"  - {name: a, driver: nosuch, credential: c, known_hosts: /k}\n" +
		"  - {name: b, address: b, driver: junos, credential: nope, known_hosts: /k}\n"
	_, err := inventory.Load(testutil.WriteInventory(t, body), testutil.KnownDrivers)
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"address is required", `unknown driver "nosuch"`, `unknown credential "nope"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

func TestInventoryLoadMissingFile(t *testing.T) {
	if _, err := inventory.Load(filepath.Join(t.TempDir(), "missing.yaml"), testutil.KnownDrivers); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestSecretResolveDetails(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := map[string]struct {
		secret inventory.Secret
		want   string
	}{
		"crlf trimmed once":      {inventory.Secret{File: write("crlf", "pw\r\n")}, "pw"},
		"only one newline":       {inventory.Secret{File: write("two", "pw\n\n")}, "pw\n"},
		"no newline":             {inventory.Secret{File: write("none", "pw")}, "pw"},
		"inner spaces preserved": {inventory.Secret{File: write("sp", " p w \n")}, " p w "},
		"literal":                {inventory.Secret{Literal: "backup"}, "backup"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := c.secret.Resolve()
			if err != nil || got != c.want {
				t.Fatalf("Resolve = %q, %v; want %q", got, err, c.want)
			}
		})
	}
	t.Setenv("TB_TEST_EMPTY", "")
	_, err := inventory.Secret{Env: "TB_TEST_EMPTY"}.Resolve()
	if !errors.Is(err, inventory.ErrCredential) {
		t.Fatalf("empty env: %v", err)
	}
	_, err = inventory.Secret{File: filepath.Join(dir, "missing")}.Resolve()
	if !errors.Is(err, inventory.ErrCredential) {
		t.Fatalf("missing file: %v", err)
	}
}

func TestSecretIsZero(t *testing.T) {
	if !(inventory.Secret{}).IsZero() {
		t.Fatal("empty secret not zero")
	}
	for _, s := range []inventory.Secret{{Env: "X"}, {File: "/x"}, {Literal: "x"}} {
		if s.IsZero() {
			t.Errorf("%+v is zero", s)
		}
	}
}
