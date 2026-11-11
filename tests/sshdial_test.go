package tests

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/whywaita/thatchbox/internal/inventory"
	"github.com/whywaita/thatchbox/internal/shell"
	"github.com/whywaita/thatchbox/internal/sshdial"
)

func simpleDevice() *fakeDevice {
	return &fakeDevice{hostname: "sw1", commands: map[string]string{"show running-config": ciscoRunning}}
}

func target(t *testing.T, s *sshServer, knownHosts string) sshdial.Target {
	t.Helper()
	h, p := hostPort(t, s.addr)
	return sshdial.Target{Host: h, Port: p, Username: "backup", Password: "pw", KnownHosts: knownHosts}
}

func runShowRun(t *testing.T, ctx context.Context, tgt sshdial.Target, jump *sshdial.Target) (string, error) {
	t.Helper()
	conn, err := sshdial.Open(ctx, tgt, jump)
	if err != nil {
		return "", err
	}
	s, err := shell.Open(ctx, conn, ciscoDriver(t), "")
	if err != nil {
		return "", err
	}
	defer s.Close()
	return s.Run(ctx, "show running-config")
}

func TestSSHCollectsOverPasswordAuth(t *testing.T) {
	srv := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", device: simpleDevice()})
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	out, err := runShowRun(t, ctx, target(t, srv, writeKnownHosts(t, srv)), nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !strings.Contains(out, "hostname example-sw") {
		t.Fatalf("unexpected output %q", out)
	}
}

func TestSSHRejectsUnknownHostKey(t *testing.T) {
	srv := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", device: simpleDevice()})
	other := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", device: simpleDevice()})
	// known_hosts holds a different server's key under this address.
	kh := writeKnownHosts(t, &sshServer{addr: srv.addr, hostKey: other.hostKey})
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err := sshdial.Open(ctx, target(t, srv, kh), nil)
	if !errors.Is(err, sshdial.ErrHostKey) {
		t.Fatalf("want ErrHostKey, got %v", err)
	}
	// An address missing from known_hosts is rejected as well.
	_, err = sshdial.Open(ctx, target(t, srv, writeKnownHosts(t, other)), nil)
	if !errors.Is(err, sshdial.ErrHostKey) {
		t.Fatalf("want ErrHostKey for unknown host, got %v", err)
	}
}

func TestSSHRequiresKnownHosts(t *testing.T) {
	srv := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", device: simpleDevice()})
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	if _, err := sshdial.Open(ctx, target(t, srv, ""), nil); err == nil {
		t.Fatal("expected error without known_hosts")
	}
}

func TestSSHWrongPassword(t *testing.T) {
	srv := startSSHServer(t, sshServerOptions{user: "backup", password: "right", device: simpleDevice()})
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err := sshdial.Open(ctx, target(t, srv, writeKnownHosts(t, srv)), nil)
	if !errors.Is(err, sshdial.ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
}

// Seen on a Catalyst 3560: password fails, then keyboard-interactive fails
// without a question, which x/crypto reports as an unexpected message.
func TestSSHWrongPasswordKeyboardInteractiveRejected(t *testing.T) {
	srv := startSSHServer(t, sshServerOptions{user: "backup", password: "right", rejectKeyboardInteractive: true, device: simpleDevice()})
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err := sshdial.Open(ctx, target(t, srv, writeKnownHosts(t, srv)), nil)
	if !errors.Is(err, sshdial.ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
}

func TestSSHConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	h, p := hostPort(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err = sshdial.Open(ctx, sshdial.Target{Host: h, Port: p, Username: "u", Password: "p", KnownHosts: writeKnownHosts(t)}, nil)
	if !errors.Is(err, sshdial.ErrConnect) {
		t.Fatalf("want ErrConnect, got %v", err)
	}
}

func TestSSHDeadlineIsTimeoutNotConnect(t *testing.T) {
	srv := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", device: simpleDevice()})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := sshdial.Open(ctx, target(t, srv, writeKnownHosts(t, srv)), nil)
	if errors.Is(err, sshdial.ErrConnect) || !errors.Is(err, context.Canceled) {
		t.Fatalf("want context error, got %v", err)
	}
}

func TestSSHLegacyCipherIsOptIn(t *testing.T) {
	srv := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", device: simpleDevice(), ciphers: []string{"aes128-cbc"}})
	kh := writeKnownHosts(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	if _, err := sshdial.Open(ctx, target(t, srv, kh), nil); err == nil {
		t.Fatal("CBC must not be offered by default")
	}
	tgt := target(t, srv, kh)
	tgt.Algorithms = inventory.SSH{Ciphers: []string{"+aes128-cbc"}}
	if _, err := runShowRun(t, ctx, tgt, nil); err != nil {
		t.Fatalf("with +aes128-cbc: %v", err)
	}
}

func TestSSHRejectsUnknownAlgorithm(t *testing.T) {
	srv := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", device: simpleDevice()})
	tgt := target(t, srv, writeKnownHosts(t, srv))
	tgt.Algorithms = inventory.SSH{KeyExchanges: []string{"+no-such-kex"}}
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	if _, err := sshdial.Open(ctx, tgt, nil); err == nil || !strings.Contains(err.Error(), "no-such-kex") {
		t.Fatalf("want unknown algorithm error, got %v", err)
	}
}

func TestSSHThroughJumpHost(t *testing.T) {
	dev := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", device: simpleDevice()})
	jump := startSSHServer(t, sshServerOptions{user: "jumper", password: "jpw", allowForward: true})
	kh := writeKnownHosts(t, dev, jump)
	jt := target(t, jump, kh)
	jt.Username, jt.Password = "jumper", "jpw"
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	out, err := runShowRun(t, ctx, target(t, dev, kh), &jt)
	if err != nil {
		t.Fatalf("via jump: %v", err)
	}
	if !strings.Contains(out, "hostname example-sw") {
		t.Fatalf("unexpected output %q", out)
	}
	if jump.Forwards() != 1 {
		t.Fatalf("jump host forwarded %d connections", jump.Forwards())
	}
}
