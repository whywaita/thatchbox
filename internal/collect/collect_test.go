package collect_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/whywaita/thatchbox/internal/collect"
	"github.com/whywaita/thatchbox/internal/driver"
	"github.com/whywaita/thatchbox/internal/inventory"
	"github.com/whywaita/thatchbox/internal/runner"
	"github.com/whywaita/thatchbox/internal/shell"
	"github.com/whywaita/thatchbox/internal/sshdial"
	"github.com/whywaita/thatchbox/internal/testutil"
)

func collectOne(t *testing.T, inv *inventory.Inventory, reg *driver.Registry, dev inventory.Device) (map[string][]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testutil.ShortTimeout)
	defer cancel()
	return (&collect.Collector{Inventory: inv, Drivers: reg}).Collect(ctx, dev)
}

func closedPort(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return testutil.HostPort(t, addr)
}

func passwordInventory(env string) *inventory.Inventory {
	return &inventory.Inventory{
		Credentials: map[string]inventory.Credential{
			"c": {Username: inventory.Secret{Literal: "backup"}, Password: inventory.Secret{Env: env}},
		},
		JumpHosts: map[string]inventory.JumpHost{},
	}
}

func TestCollectOverSSH(t *testing.T) {
	t.Setenv("TB_COLLECT_PW", "pw")
	srv := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", Password: "pw", Device: testutil.SimpleDevice()})
	h, p := testutil.HostPort(t, srv.Addr)
	dev := inventory.Device{Name: "sw1", Address: h, Port: p, Driver: "cisco_ios", Credential: "c",
		Transport: inventory.TransportSSH, KnownHosts: testutil.WriteKnownHosts(t, srv)}
	files, err := collectOne(t, passwordInventory("TB_COLLECT_PW"), testutil.Registry(t), dev)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	cfg := string(files["running-config"])
	if !strings.Contains(cfg, "hostname example-sw") || strings.Contains(cfg, "s3cr3t-comm") {
		t.Fatalf("unexpected config:\n%s", cfg)
	}
}

func TestCollectErrors(t *testing.T) {
	t.Setenv("TB_COLLECT_PW", "pw")
	reg := testutil.Registry(t)
	h, p := closedPort(t)
	ssh := inventory.Device{Name: "sw1", Address: h, Port: p, Driver: "cisco_ios", Credential: "c",
		Transport: inventory.TransportSSH, KnownHosts: testutil.WriteFile(t, "kh", nil)}
	telnetDev := ssh
	telnetDev.Transport = inventory.TransportTelnet

	cases := map[string]struct {
		inv    *inventory.Inventory
		dev    inventory.Device
		reason string
	}{
		"unknown driver": {passwordInventory("TB_COLLECT_PW"), func() inventory.Device { d := ssh; d.Driver = "nosuch"; return d }(), "error"},
		"unset secret":   {passwordInventory("TB_COLLECT_UNSET"), ssh, "credential"},
		"ssh refused":    {passwordInventory("TB_COLLECT_PW"), ssh, "connect"},
		"telnet refused": {passwordInventory("TB_COLLECT_PW"), telnetDev, "connect"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := collectOne(t, c.inv, reg, c.dev)
			if err == nil {
				t.Fatal("expected error")
			}
			if got := runner.Reason(err); got != c.reason {
				t.Fatalf("reason = %q (%v), want %q", got, err, c.reason)
			}
		})
	}
}

func TestCollectJumpHostCredentialError(t *testing.T) {
	t.Setenv("TB_COLLECT_PW", "pw")
	inv := passwordInventory("TB_COLLECT_PW")
	inv.Credentials["jc"] = inventory.Credential{Username: inventory.Secret{Literal: "j"}, Password: inventory.Secret{Env: "TB_COLLECT_UNSET"}}
	inv.JumpHosts["bastion"] = inventory.JumpHost{Address: "127.0.0.1", Port: 1, Credential: "jc", KnownHosts: testutil.WriteFile(t, "kh", nil)}
	dev := inventory.Device{Name: "sw1", Address: "127.0.0.1", Port: 1, Driver: "cisco_ios", Credential: "c",
		Transport: inventory.TransportSSH, KnownHosts: testutil.WriteFile(t, "kh", nil), Jump: "bastion"}
	_, err := collectOne(t, inv, testutil.Registry(t), dev)
	if !errors.Is(err, inventory.ErrCredential) || !strings.Contains(err.Error(), "bastion") {
		t.Fatalf("want jump host credential error, got %v", err)
	}
}

func TestCollectJumpHostUnreachable(t *testing.T) {
	t.Setenv("TB_COLLECT_PW", "pw")
	inv := passwordInventory("TB_COLLECT_PW")
	h, p := closedPort(t)
	inv.JumpHosts["bastion"] = inventory.JumpHost{Address: h, Port: p, Credential: "c", KnownHosts: testutil.WriteFile(t, "kh", nil)}
	dev := inventory.Device{Name: "sw1", Address: "192.0.2.1", Port: 22, Driver: "cisco_ios", Credential: "c",
		Transport: inventory.TransportSSH, KnownHosts: testutil.WriteFile(t, "kh", nil), Jump: "bastion"}
	_, err := collectOne(t, inv, testutil.Registry(t), dev)
	if !errors.Is(err, sshdial.ErrConnect) {
		t.Fatalf("want ErrConnect, got %v", err)
	}
}

func TestCollectTelnetLoginRejected(t *testing.T) {
	t.Setenv("TB_COLLECT_PW", "wrong")
	srv := testutil.StartTelnetServer(t, testutil.TelnetServerOptions{Password: "right", Device: testutil.SimpleDevice()})
	h, p := testutil.HostPort(t, srv.Addr)
	inv := &inventory.Inventory{Credentials: map[string]inventory.Credential{"c": {Password: inventory.Secret{Env: "TB_COLLECT_PW"}}}}
	dev := inventory.Device{Name: "sw1", Address: h, Port: p, Driver: "cisco_ios", Credential: "c", Transport: inventory.TransportTelnet}
	_, err := collectOne(t, inv, testutil.Registry(t), dev)
	if !errors.Is(err, shell.ErrLogin) {
		t.Fatalf("want ErrLogin, got %v", err)
	}
}

// A device that hangs up mid-output fails the whole device, naming the file.
func TestCollectCommandFailure(t *testing.T) {
	t.Setenv("TB_COLLECT_PW", "pw")
	srv := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", Password: "pw", Device: &testutil.FakeDevice{
		Hostname: "sw1", DropOn: "show running-config", Commands: map[string]string{"show running-config": testutil.CiscoRunning},
	}})
	h, p := testutil.HostPort(t, srv.Addr)
	dev := inventory.Device{Name: "sw1", Address: h, Port: p, Driver: "cisco_ios", Credential: "c",
		Transport: inventory.TransportSSH, KnownHosts: testutil.WriteKnownHosts(t, srv)}
	_, err := collectOne(t, passwordInventory("TB_COLLECT_PW"), testutil.Registry(t), dev)
	if !errors.Is(err, shell.ErrClosed) || !strings.HasPrefix(err.Error(), "running-config:") {
		t.Fatalf("want running-config: ErrClosed, got %v", err)
	}
}

// Output that fails validation (here: a device error message) is reported
// by category without the output.
func TestCollectProcessFailure(t *testing.T) {
	t.Setenv("TB_COLLECT_PW", "pw")
	srv := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", Password: "pw", Device: &testutil.FakeDevice{
		Hostname: "sw1", Commands: map[string]string{},
	}})
	h, p := testutil.HostPort(t, srv.Addr)
	dev := inventory.Device{Name: "sw1", Address: h, Port: p, Driver: "cisco_ios", Credential: "c",
		Transport: inventory.TransportSSH, KnownHosts: testutil.WriteKnownHosts(t, srv)}
	_, err := collectOne(t, passwordInventory("TB_COLLECT_PW"), testutil.Registry(t), dev)
	if !errors.Is(err, driver.ErrDeviceError) || strings.Contains(err.Error(), "Invalid input") {
		t.Fatalf("want ErrDeviceError without output, got %v", err)
	}
}
