package tests

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whywaita/thatchbox/internal/collect"
	"github.com/whywaita/thatchbox/internal/driver"
	"github.com/whywaita/thatchbox/internal/inventory"
	"github.com/whywaita/thatchbox/internal/runner"
	"github.com/whywaita/thatchbox/internal/shell"
	"github.com/whywaita/thatchbox/internal/telnet"
)

func telnetShowRun(t *testing.T, srv *telnetServer, login shell.Login, enable string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	h, p := hostPort(t, srv.addr)
	conn, err := telnet.Dial(ctx, h, p)
	if err != nil {
		return "", err
	}
	s, err := shell.OpenLogin(ctx, conn, ciscoDriver(t), login, enable)
	if err != nil {
		conn.Close()
		return "", err
	}
	defer s.Close()
	return s.Run(ctx, "show running-config")
}

// Seen on a Catalyst 3560: a line password without a username, then enable.
func TestTelnetLinePasswordAndEnable(t *testing.T) {
	dev := &fakeDevice{hostname: "sw1", enablePassword: "en-pw", commands: map[string]string{"show running-config": ciscoRunning}}
	srv := startTelnetServer(t, telnetServerOptions{password: "line-pw", device: dev})
	out, err := telnetShowRun(t, srv, shell.Login{Password: "line-pw"}, "en-pw")
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !strings.Contains(out, "hostname example-sw") {
		t.Fatalf("unexpected output %q", out)
	}
	if !slices.Contains(dev.Received(), "enable") {
		t.Fatalf("enable not sent: %q", dev.Received())
	}
	// Server echo and suppress-go-ahead are accepted; everything else is refused.
	want := [][3]byte{
		{tnIAC, tnDO, tnOptEcho},
		{tnIAC, tnDO, tnOptSGA},
		{tnIAC, tnWONT, tnOptTType},
		{tnIAC, tnWONT, tnOptNAWS},
	}
	if got := srv.Replies(); !slices.Equal(got, want) {
		t.Fatalf("option replies = %v, want %v", got, want)
	}
}

func TestTelnetUsernameAndPassword(t *testing.T) {
	srv := startTelnetServer(t, telnetServerOptions{username: "backup", password: "pw", device: simpleDevice()})
	out, err := telnetShowRun(t, srv, shell.Login{Username: "backup", Password: "pw"}, "")
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !strings.Contains(out, "hostname example-sw") {
		t.Fatalf("unexpected output %q", out)
	}
}

func TestTelnetWrongPassword(t *testing.T) {
	for name, o := range map[string]telnetServerOptions{
		"line password": {password: "right"},
		"username":      {username: "backup", password: "right"},
	} {
		t.Run(name, func(t *testing.T) {
			o.device = simpleDevice()
			srv := startTelnetServer(t, o)
			_, err := telnetShowRun(t, srv, shell.Login{Username: "backup", Password: "wrong"}, "")
			if !errors.Is(err, shell.ErrLogin) {
				t.Fatalf("want ErrLogin, got %v", err)
			}
			if strings.Contains(err.Error(), "Login invalid") {
				t.Fatalf("error leaks device output: %v", err)
			}
			if runner.Reason(err) != "auth" {
				t.Fatalf("reason = %q", runner.Reason(err))
			}
		})
	}
}

func TestTelnetUsernameRequiredButMissing(t *testing.T) {
	srv := startTelnetServer(t, telnetServerOptions{username: "backup", password: "pw", device: simpleDevice()})
	_, err := telnetShowRun(t, srv, shell.Login{Password: "pw"}, "")
	if !errors.Is(err, shell.ErrLogin) {
		t.Fatalf("want ErrLogin, got %v", err)
	}
}

func TestTelnetConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	h, p := hostPort(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err = telnet.Dial(ctx, h, p)
	if !errors.Is(err, telnet.ErrConnect) {
		t.Fatalf("want ErrConnect, got %v", err)
	}
	if runner.Reason(err) != "connect" {
		t.Fatalf("reason = %q", runner.Reason(err))
	}
}

// The data path: IAC IAC is a literal 0xFF, CR NUL is a bare CR, and the
// client escapes 0xFF and sends CR LF for a newline.
func TestTelnetDataEncoding(t *testing.T) {
	client, server := net.Pipe()
	conn := telnet.NewConn(client)
	defer conn.Close()
	defer server.Close()

	go func() {
		_, _ = server.Write([]byte{'a', tnIAC, tnIAC, 'b', '\r', 0, 'c', '\r', '\n'})
	}()
	got := make([]byte, 0, 16)
	buf := make([]byte, 16)
	for len(got) < 7 {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, buf[:n]...)
	}
	if want := []byte{'a', tnIAC, 'b', '\r', 'c', '\r', '\n'}; !bytes.Equal(got, want) {
		t.Fatalf("read %v, want %v", got, want)
	}

	go func() { _, _ = io.WriteString(conn, "x\xffy\n") }()
	want := []byte{'x', tnIAC, tnIAC, 'y', '\r', '\n'}
	sent := make([]byte, len(want))
	if _, err := io.ReadFull(server, sent); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sent, want) {
		t.Fatalf("wrote %v, want %v", sent, want)
	}
}

// The inventory path: a telnet device needs no known_hosts and no username.
func TestCollectOverTelnetFromInventory(t *testing.T) {
	dev := &fakeDevice{hostname: "sw1", enablePassword: "en-pw", commands: map[string]string{"show running-config": ciscoRunning}}
	srv := startTelnetServer(t, telnetServerOptions{password: "line-pw", device: dev})
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	h, p := hostPort(t, srv.addr)
	invPath := writeInventory(t, fmt.Sprintf(`
credentials:
  line:
    password: {file: %s}
    enable_password: {file: %s}
devices:
  - {name: sw1, address: %s, port: %d, driver: cisco_ios, credential: line, transport: telnet}
`, write("pw", "line-pw\n"), write("enable", "en-pw\n"), h, p))
	reg, err := driver.Load("")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.Load(invPath, func(n string) bool { _, ok := reg.Get(n); return ok })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	files, err := (&collect.Collector{Inventory: inv, Drivers: reg}).Collect(ctx, inv.Devices[0])
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !strings.Contains(string(files["running-config"]), "hostname example-sw") {
		t.Fatalf("unexpected files %v", files)
	}
}
