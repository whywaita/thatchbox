package tests

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"testing"

	"github.com/whywaita/thatchbox/internal/runner"
	"github.com/whywaita/thatchbox/internal/shell"
	"github.com/whywaita/thatchbox/internal/sshdial"
	"github.com/whywaita/thatchbox/internal/telnet"
)

func TestShellEnableNeedsPassword(t *testing.T) {
	dev := &fakeDevice{hostname: "sw1", enablePassword: "secret"}
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err := shell.Open(ctx, dev.connect(), ciscoDriver(t), "")
	if !errors.Is(err, shell.ErrEnable) {
		t.Fatalf("want ErrEnable, got %v", err)
	}
	if runner.Reason(err) != "enable" {
		t.Fatalf("reason = %q", runner.Reason(err))
	}
}

// A device that is already privileged never receives the enable command.
func TestShellSkipsEnableWhenPrivileged(t *testing.T) {
	dev := &fakeDevice{hostname: "sw1", commands: map[string]string{"show running-config": ciscoRunning}}
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	s, err := shell.Open(ctx, dev.connect(), ciscoDriver(t), "unused")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if slices.Contains(dev.Received(), "enable") {
		t.Fatalf("enable sent to a privileged prompt: %q", dev.Received())
	}
}

func TestShellClosedBeforePrompt(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		_, _ = io.WriteString(server, "banner only\r\n")
		server.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err := shell.Open(ctx, client, ciscoDriver(t), "")
	if !errors.Is(err, shell.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}

func TestShellRunAfterClose(t *testing.T) {
	dev := simpleDevice()
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	s, err := shell.Open(ctx, dev.connect(), ciscoDriver(t), "")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s.Close() // idempotent
	if _, err := s.Run(ctx, "show running-config"); !errors.Is(err, shell.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}

func TestSSHShellRejected(t *testing.T) {
	srv := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", device: simpleDevice(), rejectPTY: true})
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err := sshdial.Open(ctx, target(t, srv, writeKnownHosts(t, srv)), nil)
	if !errors.Is(err, sshdial.ErrSession) {
		t.Fatalf("want ErrSession, got %v", err)
	}
	if runner.Reason(err) != "session" {
		t.Fatalf("reason = %q", runner.Reason(err))
	}
}

func TestSSHBadPrivateKey(t *testing.T) {
	srv := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", device: simpleDevice()})
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	tgt := keyTarget(t, srv, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"))
	_, err := sshdial.Open(ctx, tgt, nil)
	if err == nil || bytes.Contains([]byte(err.Error()), []byte("AAAA")) {
		t.Fatalf("want a parse error without key material, got %v", err)
	}
}

func TestSSHNoCredentials(t *testing.T) {
	srv := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", device: simpleDevice()})
	tgt := target(t, srv, writeKnownHosts(t, srv))
	tgt.Password = ""
	_, err := sshdial.Open(context.Background(), tgt, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSSHMixedAlgorithmOverride(t *testing.T) {
	srv := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", device: simpleDevice()})
	tgt := target(t, srv, writeKnownHosts(t, srv))
	tgt.Algorithms.Ciphers = []string{"+aes128-cbc", "aes256-ctr"}
	_, err := sshdial.Open(context.Background(), tgt, nil)
	if err == nil {
		t.Fatal("mixed + and plain names accepted")
	}
}

func TestSSHJumpHostRejectsForwarding(t *testing.T) {
	dev := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", device: simpleDevice()})
	jump := startSSHServer(t, sshServerOptions{user: "backup", password: "pw", allowForward: false})
	kh := writeKnownHosts(t, dev, jump)
	jt := target(t, jump, kh)
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err := sshdial.Open(ctx, target(t, dev, kh), &jt)
	if !errors.Is(err, sshdial.ErrConnect) {
		t.Fatalf("want ErrConnect, got %v", err)
	}
}

// Each option request is answered once, DONT/WONT are not answered, and an
// IAC IAC inside a subnegotiation does not end it.
func TestTelnetNegotiationEdgeCases(t *testing.T) {
	client, server := net.Pipe()
	conn := telnet.NewConn(client)
	defer conn.Close()
	defer server.Close()

	go func() {
		_, _ = server.Write([]byte{
			tnIAC, tnDO, tnOptNAWS,
			tnIAC, tnDO, tnOptNAWS, // repeated: no second reply
			tnIAC, tnDONT, tnOptEcho, tnIAC, tnWONT, tnOptSGA, // no replies
			tnIAC, tnSB, tnOptTType, tnIAC, tnIAC, 'x', tnIAC, tnSE,
			tnIAC, 241, // NOP is ignored
			'o', 'k',
		})
	}()
	replies := make(chan []byte, 1)
	go func() {
		b := make([]byte, 3)
		_, _ = io.ReadFull(server, b)
		replies <- b
	}()
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "ok" {
		t.Fatalf("data = %q", got)
	}
	if got := <-replies; !bytes.Equal(got, []byte{tnIAC, tnWONT, tnOptNAWS}) {
		t.Fatalf("reply = %v", got)
	}
	if n, err := conn.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read = %d %v", n, err)
	}
}

func TestTelnetReadReturnsEOF(t *testing.T) {
	client, server := net.Pipe()
	conn := telnet.NewConn(client)
	defer conn.Close()
	go func() {
		_, _ = server.Write([]byte{tnIAC, tnWILL, tnOptEcho})
		server.Close()
	}()
	go func() { _, _ = io.Copy(io.Discard, server) }()
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
}

func TestTelnetWriteAfterClose(t *testing.T) {
	client, server := net.Pipe()
	server.Close()
	conn := telnet.NewConn(client)
	if _, err := conn.Write([]byte("x\n")); err == nil {
		t.Fatal("write to closed connection succeeded")
	}
}
