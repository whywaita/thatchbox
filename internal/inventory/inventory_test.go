package inventory_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whywaita/thatchbox/internal/inventory"
	"github.com/whywaita/thatchbox/internal/testutil"
)

func TestInventoryLoadAppliesDefaults(t *testing.T) {
	inv, err := inventory.Load(testutil.WriteInventory(t, testutil.ValidInventory), testutil.KnownDrivers)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if inv.Defaults.Concurrency != 4 {
		t.Errorf("concurrency = %d", inv.Defaults.Concurrency)
	}
	if len(inv.Devices) != 3 {
		t.Fatalf("devices = %d", len(inv.Devices))
	}
	sw := inv.Devices[0]
	if sw.Port != 22 || time.Duration(sw.Timeout) != 90*time.Second || sw.KnownHosts != "/etc/thatchbox/known_hosts" || !sw.IsEnabled() {
		t.Errorf("defaults not applied: %+v", sw)
	}
	r1 := inv.Devices[1]
	if r1.Port != 2222 || time.Duration(r1.Timeout) != 5*time.Minute || r1.Jump != "bastion" {
		t.Errorf("overrides lost: %+v", r1)
	}
	if inv.Devices[2].IsEnabled() {
		t.Errorf("old-ix should be disabled")
	}
	if inv.Defaults.MinSizeRatio != inventory.DefaultMinSizeRatio {
		t.Errorf("min size ratio = %v", inv.Defaults.MinSizeRatio)
	}
}

func TestInventoryRejectsInvalid(t *testing.T) {
	cases := map[string]struct{ from, to string }{
		"unknown driver":      {"driver: junos", "driver: nosuch"},
		"unknown credential":  {"credential: keyonly\n    jump", "credential: missing\n    jump"},
		"unknown jump host":   {"jump: bastion", "jump: missing"},
		"duplicate name":      {"name: edge.r1", "name: core-sw1"},
		"path in name":        {"name: edge.r1", "name: ../r1"},
		"literal password":    {"password: {env: TB_TEST_PASSWORD}", "password: hunter2"},
		"missing address":     {"address: 192.0.2.2\n", "\n"},
		"unknown field":       {"enabled: false", "enabeld: false"},
		"no known_hosts":      {"known_hosts: /etc/thatchbox/known_hosts", "known_hosts: \"\""},
		"secret env and file": {"password: {env: TB_TEST_PASSWORD}", "password: {env: A, file: /b}"},
		"bad duration":        {"timeout: 5m", "timeout: soon"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(testutil.ValidInventory, c.from, c.to, 1)
			if body == testutil.ValidInventory {
				t.Fatalf("replacement %q not applied", c.from)
			}
			if _, err := inventory.Load(testutil.WriteInventory(t, body), testutil.KnownDrivers); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

const telnetInventory = `
credentials:
  line:
    password: {env: TB_TEST_PASSWORD}
    enable_password: {env: TB_TEST_ENABLE}
  ssh:
    username: backup
    password: {env: TB_TEST_PASSWORD}
devices:
  - name: old-sw
    address: 192.0.2.4
    driver: cisco_ios
    credential: line
    transport: telnet
  - name: other-sw
    address: 192.0.2.5
    port: 2323
    driver: cisco_ios
    credential: ssh
    transport: telnet
`

func TestInventoryTelnetDevice(t *testing.T) {
	inv, err := inventory.Load(testutil.WriteInventory(t, telnetInventory), testutil.KnownDrivers)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	sw := inv.Devices[0]
	if sw.Transport != inventory.TransportTelnet || sw.Port != inventory.DefaultTelnetPort {
		t.Errorf("telnet defaults not applied: %+v", sw)
	}
	if inv.Devices[1].Port != 2323 {
		t.Errorf("port override lost: %+v", inv.Devices[1])
	}
	ssh, err := inventory.Load(testutil.WriteInventory(t, testutil.ValidInventory), testutil.KnownDrivers)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.Devices[0].Transport != inventory.TransportSSH {
		t.Errorf("default transport = %q", ssh.Devices[0].Transport)
	}
}

func TestInventoryRejectsInvalidTelnet(t *testing.T) {
	cases := map[string]struct {
		body     string
		from, to string
	}{
		"unknown transport":           {telnetInventory, "transport: telnet\n  - name: other", "transport: rsh\n  - name: other"},
		"telnet without password":     {telnetInventory, "  line:\n    password: {env: TB_TEST_PASSWORD}\n", "  line:\n"},
		"telnet through a jump host":  {telnetInventory, "transport: telnet\n  - name: other", "transport: telnet\n    jump: bastion\n  - name: other"},
		"ssh device without username": {telnetInventory, "credential: ssh\n    transport: telnet", "credential: line"},
		"jump host without username":  {testutil.ValidInventory, "username: {env: TB_TEST_USER}\n", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(c.body, c.from, c.to, 1)
			if body == c.body {
				t.Fatalf("replacement %q not applied", c.from)
			}
			if !strings.Contains(body, "jump_hosts") {
				body += "jump_hosts:\n  bastion: {address: bastion.example.net, credential: ssh, known_hosts: /k}\n"
			}
			if _, err := inventory.Load(testutil.WriteInventory(t, body), testutil.KnownDrivers); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSecretResolve(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "pw")
	if err := os.WriteFile(file, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TB_TEST_PASSWORD", "from-env")

	got, err := inventory.Secret{Env: "TB_TEST_PASSWORD"}.Resolve()
	if err != nil || got != "from-env" {
		t.Fatalf("env: %q %v", got, err)
	}
	got, err = inventory.Secret{File: file}.Resolve()
	if err != nil || got != "from-file" {
		t.Fatalf("file: %q %v", got, err)
	}
	if _, err := (inventory.Secret{Env: "TB_TEST_UNSET_VARIABLE"}).Resolve(); err == nil {
		t.Fatal("unset env should fail")
	}
	if _, err := (inventory.Secret{File: filepath.Join(dir, "missing")}).Resolve(); err == nil {
		t.Fatal("missing file should fail")
	}
	got, err = inventory.Secret{}.Resolve()
	if err != nil || got != "" {
		t.Fatalf("empty secret: %q %v", got, err)
	}
}
