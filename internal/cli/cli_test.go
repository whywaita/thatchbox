package cli_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/whywaita/thatchbox/internal/cli"
	"github.com/whywaita/thatchbox/internal/testutil"
)

func cliInventory(t *testing.T, knownHosts string, devs ...*testutil.SSHServer) string {
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
		h, p := testutil.HostPort(t, s.Addr)
		fmt.Fprintf(&b, "  - {name: dev%d, address: %s, port: %d, driver: cisco_ios, credential: lab}\n", i, h, p)
	}
	return testutil.WriteInventory(t, b.String())
}

func TestCLIRunEndToEnd(t *testing.T) {
	t.Setenv("TB_CLI_PASSWORD", "pw")
	ok := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", Password: "pw", Device: testutil.SimpleDevice()})
	broken := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", Password: "pw", Device: &testutil.FakeDevice{
		Hostname: "sw2",
		DropOn:   "show running-config",
		Commands: map[string]string{"show running-config": testutil.CiscoRunning},
	}})
	inv := cliInventory(t, testutil.WriteKnownHosts(t, ok, broken), ok, broken)
	remote := testutil.NewRemote(t)

	var stderr bytes.Buffer
	code := cli.Main([]string{"run", "--inventory", inv, "--repo", remote}, &stderr)
	if code != cli.ExitDeviceFailures {
		t.Fatalf("exit code %d, stderr:\n%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "$9$") || strings.Contains(stderr.String(), "s3cr3t") {
		t.Fatalf("log leaks device output:\n%s", stderr.String())
	}
	repo := testutil.OpenStore(t, remote)
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
	inv := testutil.WriteInventory(t, testutil.ValidInventory)
	var stderr bytes.Buffer
	if code := cli.Main([]string{"validate", "--inventory", inv}, &stderr); code != cli.ExitOK {
		t.Fatalf("validate: %d %s", code, stderr.String())
	}
	bad := testutil.WriteInventory(t, strings.Replace(testutil.ValidInventory, "driver: junos", "driver: nosuch", 1))
	if code := cli.Main([]string{"validate", "--inventory", bad}, &stderr); code != cli.ExitFatal {
		t.Fatalf("invalid inventory accepted: %d", code)
	}
}

func TestExampleInventoryIsValid(t *testing.T) {
	var stderr bytes.Buffer
	if code := cli.Main([]string{"validate", "--inventory", "../../examples/inventory.yaml"}, &stderr); code != cli.ExitOK {
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
