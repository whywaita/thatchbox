package tests

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/whywaita/thatchbox/internal/shell"
)

const shortTimeout = 2 * time.Second

func TestShellRunsCommandAfterEnableAndSetup(t *testing.T) {
	dev := &fakeDevice{
		hostname:       "sw1",
		banner:         "Authorized access only",
		enablePassword: "enpw",
		commands:       map[string]string{"show running-config": ciscoRunning},
	}
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	s, err := shell.Open(ctx, dev.connect(), ciscoDriver(t), "enpw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	out, err := s.Run(ctx, "show running-config")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(out, "show running-config") || strings.Contains(out, "sw1#") {
		t.Fatalf("echo or prompt not removed:\n%q", out)
	}
	if !strings.Contains(out, "hostname example-sw") || !strings.HasSuffix(strings.TrimSpace(out), "end") {
		t.Fatalf("unexpected output:\n%q", out)
	}
	if got := dev.Received(); !slices.Contains(got, "terminal length 0") || !slices.Contains(got, "enable") {
		t.Fatalf("setup/enable not sent: %v", got)
	}
}

func TestShellAnswersPager(t *testing.T) {
	long := strings.Repeat("interface x\n description y\n", 20) + "end\n"
	dev := &fakeDevice{
		hostname:  "sw1",
		pageEvery: 7,
		commands:  map[string]string{"show running-config": long},
	}
	// A driver without setup so the pager is never disabled.
	d := mustParse(t, `
name: paged
prompt: '^[\w.\-]+[>#]\s*$'
pager: {pattern: '\s*--More--\s*$', send: ' '}
outputs: [{path: cfg, command: show running-config, end: '^end$'}]
`)
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	s, err := shell.Open(ctx, dev.connect(), d, "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	out, err := s.Run(ctx, "show running-config")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got, err := d.Process(d.Outputs[0], out)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got != long {
		t.Fatalf("paged output mangled:\n%q", got)
	}
}

func TestShellWrongEnablePassword(t *testing.T) {
	dev := &fakeDevice{hostname: "sw1", enablePassword: "right"}
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	_, err := shell.Open(ctx, dev.connect(), ciscoDriver(t), "wrong")
	if !errors.Is(err, shell.ErrEnable) {
		t.Fatalf("want ErrEnable, got %v", err)
	}
}

func TestShellTimesOutWithoutLeakingOutput(t *testing.T) {
	dev := &fakeDevice{
		hostname: "sw1",
		stallOn:  "show running-config",
		commands: map[string]string{"show running-config": "secret-token-in-output\n"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	s, err := shell.Open(ctx, dev.connect(), ciscoDriver(t), "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	runCtx, runCancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer runCancel()
	_, err = s.Run(runCtx, "show running-config")
	if !errors.Is(err, shell.ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("error leaks output: %v", err)
	}
}

func TestShellConnectionClosedMidOutput(t *testing.T) {
	dev := &fakeDevice{
		hostname: "sw1",
		dropOn:   "show running-config",
		commands: map[string]string{"show running-config": ciscoRunning},
	}
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	s, err := shell.Open(ctx, dev.connect(), ciscoDriver(t), "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if _, err := s.Run(ctx, "show running-config"); !errors.Is(err, shell.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}

// Seen on an IX2215: the login prompt is already "#", show running-config
// needs configuration mode (enable-config, no password), the pager cannot be
// disabled, and each pager prompt is erased with "\b \b" pairs.
func TestShellNECIXEnableConfig(t *testing.T) {
	cfg := "! NEC Portable Internetwork Core Operating System Software\n!\nhostname example-ix\n  ip address 192.0.2.1/24\n  no shutdown\n!\ninterface GigaEthernet1.0\n  no ip address\n  no shutdown\n"
	dev := &fakeDevice{
		hostname:      "ix",
		userSuffix:    "# ",
		privSuffix:    "(config)# ",
		enableCommand: "enable-config",
		privCommands:  true,
		pageEvery:     2,
		pagerErase:    strings.Repeat("\b \b", 8),
		commands:      map[string]string{"show running-config": cfg},
	}
	d, _ := mustRegistry(t).Get("nec_ix")
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	s, err := shell.Open(ctx, dev.connect(), d, "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	out, err := s.Run(ctx, d.Outputs[0].Command)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got, err := d.Process(d.Outputs[0], out)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got != cfg {
		t.Fatalf("unexpected:\n%q\nwant\n%q", got, cfg)
	}
	if !slices.Contains(dev.Received(), "enable-config") {
		t.Fatalf("enable-config not sent: %v", dev.Received())
	}
}

func TestShellJunosPrompt(t *testing.T) {
	cfg := "version 21.4R3;\nsystem {\n    host-name r1;\n}\n\n{master:0}\n"
	dev := &fakeDevice{
		hostname:   "admin@r1",
		privSuffix: "> ",
		commands: map[string]string{
			"show configuration | no-more": cfg,
			"set cli screen-length 0":      "Screen length set to 0\n",
			"set cli screen-width 0":       "Screen width set to 0\n",
		},
	}
	reg := mustRegistry(t)
	d, _ := reg.Get("junos")
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	s, err := shell.Open(ctx, dev.connect(), d, "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	out, err := s.Run(ctx, d.Outputs[0].Command)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got, err := d.Process(d.Outputs[0], out)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got != "version 21.4R3;\nsystem {\n    host-name r1;\n}\n" {
		t.Fatalf("unexpected:\n%q", got)
	}
}
