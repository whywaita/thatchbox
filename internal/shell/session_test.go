package shell_test

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"testing"

	"github.com/whywaita/thatchbox/internal/runner"
	"github.com/whywaita/thatchbox/internal/shell"
	"github.com/whywaita/thatchbox/internal/testutil"
)

func TestShellEnableNeedsPassword(t *testing.T) {
	dev := &testutil.FakeDevice{Hostname: "sw1", EnablePassword: "secret"}
	ctx, cancel := context.WithTimeout(context.Background(), testutil.ShortTimeout)
	defer cancel()
	_, err := shell.Open(ctx, dev.Connect(), testutil.CiscoDriver(t), "")
	if !errors.Is(err, shell.ErrEnable) {
		t.Fatalf("want ErrEnable, got %v", err)
	}
	if runner.Reason(err) != "enable" {
		t.Fatalf("reason = %q", runner.Reason(err))
	}
}

// A device that is already privileged never receives the enable command.

func TestShellSkipsEnableWhenPrivileged(t *testing.T) {
	dev := &testutil.FakeDevice{Hostname: "sw1", Commands: map[string]string{"show running-config": testutil.CiscoRunning}}
	ctx, cancel := context.WithTimeout(context.Background(), testutil.ShortTimeout)
	defer cancel()
	s, err := shell.Open(ctx, dev.Connect(), testutil.CiscoDriver(t), "unused")
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
	ctx, cancel := context.WithTimeout(context.Background(), testutil.ShortTimeout)
	defer cancel()
	_, err := shell.Open(ctx, client, testutil.CiscoDriver(t), "")
	if !errors.Is(err, shell.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}

func TestShellRunAfterClose(t *testing.T) {
	dev := testutil.SimpleDevice()
	ctx, cancel := context.WithTimeout(context.Background(), testutil.ShortTimeout)
	defer cancel()
	s, err := shell.Open(ctx, dev.Connect(), testutil.CiscoDriver(t), "")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s.Close() // idempotent
	if _, err := s.Run(ctx, "show running-config"); !errors.Is(err, shell.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}
