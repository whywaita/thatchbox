package tests

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/whywaita/thatchbox/internal/cli"
)

func cliInventory(t *testing.T, knownHosts string, devs ...*sshServer) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, `
defaults:
  known_hosts: %s
  timeout: 2s
credentials:
  lab:
    username: backup
    password: {env: TB_CLI_PASSWORD}
devices:
`, knownHosts)
	for i, s := range devs {
		h, p := hostPort(t, s.addr)
		fmt.Fprintf(&b, "  - {name: dev%d, address: %s, port: %d, driver: cisco_ios, credential: lab}\n", i, h, p)
	}
	return writeInventory(t, b.String())
}

func TestCLIRunEndToEnd(t *testing.T) {
	t.Setenv("TB_CLI_PASSWORD", "pw")
	ok := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", device: simpleDevice()})
	broken := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", device: &fakeDevice{
		hostname: "sw2",
		dropOn:   "show running-config",
		commands: map[string]string{"show running-config": ciscoRunning},
	}})
	inv := cliInventory(t, writeKnownHosts(t, ok, broken), ok, broken)
	remote := newRemote(t)

	var stderr bytes.Buffer
	code := cli.Main([]string{"run", "--inventory", inv, "--repo", remote}, &stderr)
	if code != cli.ExitDeviceFailures {
		t.Fatalf("exit code %d, stderr:\n%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "$9$") || strings.Contains(stderr.String(), "s3cr3t") {
		t.Fatalf("log leaks device output:\n%s", stderr.String())
	}
	repo := openStore(t, remote)
	files, err := repo.ReadDevice("dev0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(files["running-config"])
	if !strings.Contains(cfg, "hostname example-sw") || strings.Contains(cfg, "s3cr3t-comm") {
		t.Fatalf("unexpected stored config:\n%s", cfg)
	}
	st, _ := repo.ReadStatus()
	if st.Devices["dev1"].Reason != "closed" {
		t.Fatalf("dev1 status: %+v", st.Devices["dev1"])
	}
}

func TestCLIValidate(t *testing.T) {
	inv := writeInventory(t, validInventory)
	var stderr bytes.Buffer
	if code := cli.Main([]string{"validate", "--inventory", inv}, &stderr); code != cli.ExitOK {
		t.Fatalf("validate: %d %s", code, stderr.String())
	}
	bad := writeInventory(t, strings.Replace(validInventory, "driver: junos", "driver: nosuch", 1))
	if code := cli.Main([]string{"validate", "--inventory", bad}, &stderr); code != cli.ExitFatal {
		t.Fatalf("invalid inventory accepted: %d", code)
	}
}

func TestExampleInventoryIsValid(t *testing.T) {
	var stderr bytes.Buffer
	if code := cli.Main([]string{"validate", "--inventory", "../examples/inventory.yaml"}, &stderr); code != cli.ExitOK {
		t.Fatalf("examples/inventory.yaml: %d %s", code, stderr.String())
	}
}

func TestCLIUsageErrors(t *testing.T) {
	var stderr bytes.Buffer
	for _, args := range [][]string{
		nil,
		{"nosuch"},
		{"run", "--inventory", "x"},
		{"run", "--inventory", "x", "--repo", "y", "--git-ssh-key", "k"},
	} {
		if code := cli.Main(args, &stderr); code != cli.ExitFatal {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}
