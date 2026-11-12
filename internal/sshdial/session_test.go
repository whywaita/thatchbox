package sshdial_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/whywaita/thatchbox/internal/runner"
	"github.com/whywaita/thatchbox/internal/sshdial"
	"github.com/whywaita/thatchbox/internal/testutil"
)

func TestSSHShellRejected(t *testing.T) {
	srv := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", Password: "pw", Device: testutil.SimpleDevice(), RejectPTY: true})
	ctx, cancel := context.WithTimeout(context.Background(), testutil.ShortTimeout)
	defer cancel()
	_, err := sshdial.Open(ctx, target(t, srv, testutil.WriteKnownHosts(t, srv)), nil)
	if !errors.Is(err, sshdial.ErrSession) {
		t.Fatalf("want ErrSession, got %v", err)
	}
	if runner.Reason(err) != "session" {
		t.Fatalf("reason = %q", runner.Reason(err))
	}
}

func TestSSHBadPrivateKey(t *testing.T) {
	srv := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", Password: "pw", Device: testutil.SimpleDevice()})
	ctx, cancel := context.WithTimeout(context.Background(), testutil.ShortTimeout)
	defer cancel()
	tgt := keyTarget(t, srv, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"))
	_, err := sshdial.Open(ctx, tgt, nil)
	if err == nil || bytes.Contains([]byte(err.Error()), []byte("AAAA")) {
		t.Fatalf("want a parse error without key material, got %v", err)
	}
}

func TestSSHNoCredentials(t *testing.T) {
	srv := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", Password: "pw", Device: testutil.SimpleDevice()})
	tgt := target(t, srv, testutil.WriteKnownHosts(t, srv))
	tgt.Password = ""
	_, err := sshdial.Open(context.Background(), tgt, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSSHMixedAlgorithmOverride(t *testing.T) {
	srv := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", Password: "pw", Device: testutil.SimpleDevice()})
	tgt := target(t, srv, testutil.WriteKnownHosts(t, srv))
	tgt.Algorithms.Ciphers = []string{"+aes128-cbc", "aes256-ctr"}
	_, err := sshdial.Open(context.Background(), tgt, nil)
	if err == nil {
		t.Fatal("mixed + and plain names accepted")
	}
}

func TestSSHJumpHostRejectsForwarding(t *testing.T) {
	dev := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", Password: "pw", Device: testutil.SimpleDevice()})
	jump := testutil.StartSSHServer(t, testutil.SSHServerOptions{User: "backup", Password: "pw", AllowForward: false})
	kh := testutil.WriteKnownHosts(t, dev, jump)
	jt := target(t, jump, kh)
	ctx, cancel := context.WithTimeout(context.Background(), testutil.ShortTimeout)
	defer cancel()
	_, err := sshdial.Open(ctx, target(t, dev, kh), &jt)
	if !errors.Is(err, sshdial.ErrConnect) {
		t.Fatalf("want ErrConnect, got %v", err)
	}
}

// Each option request is answered once, DONT/WONT are not answered, and an
// IAC IAC inside a subnegotiation does not end it.
