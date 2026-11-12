package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whywaita/thatchbox/internal/cli"
	"github.com/whywaita/thatchbox/internal/testutil"
)

func TestCLIVersion(t *testing.T) {
	var out bytes.Buffer
	if code := cli.Main([]string{"version"}, &out); code != cli.ExitOK {
		t.Fatalf("exit %d", code)
	}
	if got := strings.TrimSpace(out.String()); got != cli.Version {
		t.Fatalf("version = %q, want %q", got, cli.Version)
	}
}

func TestCLIUsageListsCommands(t *testing.T) {
	var out bytes.Buffer
	if code := cli.Main(nil, &out); code != cli.ExitFatal {
		t.Fatalf("exit %d", code)
	}
	for _, cmd := range []string{"run", "validate", "drivers", "version"} {
		if !strings.Contains(out.String(), cmd) {
			t.Errorf("usage does not mention %q:\n%s", cmd, out.String())
		}
	}
}

func TestCLIDriversListsBuiltinsSorted(t *testing.T) {
	var out bytes.Buffer
	if code := cli.Main([]string{"drivers"}, &out); code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	got := strings.Fields(out.String())
	if want := []string{"cisco_ios", "junos", "nec_ix"}; !slices.Equal(got, want) {
		t.Fatalf("drivers = %q, want %q", got, want)
	}
}

func TestCLIDriversIncludesDirectory(t *testing.T) {
	dir := t.TempDir()
	def := "name: aaa_custom\nprompt: '#$'\noutputs: [{path: cfg, command: show}]\n"
	if err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(def), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := cli.Main([]string{"drivers", "--drivers", dir}, &out); code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if got := strings.Fields(out.String()); len(got) != 4 || got[0] != "aaa_custom" {
		t.Fatalf("drivers = %q", got)
	}
}

func TestCLIDriversErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"missing directory": {"drivers", "--drivers", filepath.Join(t.TempDir(), "missing")},
		"unknown flag":      {"drivers", "--nosuch"},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if code := cli.Main(args, &out); code != cli.ExitFatal {
				t.Fatalf("exit %d", code)
			}
		})
	}
}

func TestCLIValidateErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no inventory":      {"validate"},
		"missing inventory": {"validate", "--inventory", filepath.Join(t.TempDir(), "missing.yaml")},
		"unknown flag":      {"validate", "--nosuch"},
		"bad drivers dir":   {"validate", "--inventory", "../../examples/inventory.yaml", "--drivers", filepath.Join(t.TempDir(), "missing")},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if code := cli.Main(args, &out); code != cli.ExitFatal {
				t.Fatalf("exit %d", code)
			}
		})
	}
}

func TestCLIRunFlagErrors(t *testing.T) {
	key, _ := testutil.ClientKey(t, "")
	keyFile := testutil.WriteFile(t, "key", key)
	knownHosts := testutil.WriteFile(t, "known_hosts", nil)
	inv := testutil.WriteInventory(t, testutil.ValidInventory)
	remote := testutil.NewRemote(t)
	cases := map[string][]string{
		"unknown flag":            {"run", "--nosuch"},
		"bad log level":           {"run", "--inventory", inv, "--repo", remote, "--log-level", "loud"},
		"no repo":                 {"run", "--inventory", inv},
		"no inventory":            {"run", "--repo", remote},
		"key without known_hosts": {"run", "--inventory", inv, "--repo", remote, "--git-ssh-key", keyFile},
		"unreadable key":          {"run", "--inventory", inv, "--repo", remote, "--git-ssh-key", testutil.WriteFile(t, "bad", []byte("not a key")), "--git-known-hosts", knownHosts},
		"missing known_hosts":     {"run", "--inventory", inv, "--repo", remote, "--git-ssh-key", keyFile, "--git-known-hosts", filepath.Join(t.TempDir(), "missing")},
		"unreachable remote":      {"run", "--inventory", inv, "--repo", filepath.Join(t.TempDir(), "no-such-remote")},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if code := cli.Main(args, &out); code != cli.ExitFatal {
				t.Fatalf("exit %d: %s", code, out.String())
			}
		})
	}
}

// A run where every device succeeds exits 0, keeps an explicit workdir, and
// accepts a git SSH key (a local remote does not use it).
func TestCLIRunAllDevicesOK(t *testing.T) {
	t.Setenv("TB_CLI_PASSWORD", "pw")
	srv := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", Password: "pw", Device: testutil.SimpleDevice()})
	inv := cliInventory(t, testutil.WriteKnownHosts(t, srv), srv)
	key, _ := testutil.ClientKey(t, "")
	workdir := filepath.Join(t.TempDir(), "work")

	var out bytes.Buffer
	code := cli.Main([]string{
		"run", "--inventory", inv, "--repo", testutil.NewRemote(t), "--workdir", workdir,
		"--git-ssh-key", testutil.WriteFile(t, "key", key), "--git-known-hosts", testutil.WriteFile(t, "known_hosts", nil),
		"--author-name", "bot", "--author-email", "bot@example.invalid", "--log-level", "debug",
	}, &out)
	if code != cli.ExitOK {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
	if _, err := os.Stat(filepath.Join(workdir, "configs", "dev0", "running-config")); err != nil {
		t.Fatalf("workdir not kept: %v", err)
	}
}

// A repository whose status.json is corrupt cannot be updated: that is
// fatal, not a device failure.
func TestCLIRunCorruptStatusIsFatal(t *testing.T) {
	t.Setenv("TB_CLI_PASSWORD", "pw")
	srv := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", Password: "pw", Device: testutil.SimpleDevice()})
	inv := cliInventory(t, testutil.WriteKnownHosts(t, srv), srv)
	remote := testutil.RemoteWithStatus(t, "{")
	var out bytes.Buffer
	if code := cli.Main([]string{"run", "--inventory", inv, "--repo", remote}, &out); code != cli.ExitFatal {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
}
