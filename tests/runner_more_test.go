package tests

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/whywaita/thatchbox/internal/driver"
	"github.com/whywaita/thatchbox/internal/inventory"
	"github.com/whywaita/thatchbox/internal/runner"
	"github.com/whywaita/thatchbox/internal/shell"
	"github.com/whywaita/thatchbox/internal/sshdial"
	"github.com/whywaita/thatchbox/internal/telnet"
)

func TestReason(t *testing.T) {
	cases := map[error]string{
		sshdial.ErrHostKey:       "host-key",
		sshdial.ErrAuth:          "auth",
		shell.ErrLogin:           "auth",
		sshdial.ErrConnect:       "connect",
		telnet.ErrConnect:        "connect",
		sshdial.ErrSession:       "session",
		shell.ErrEnable:          "enable",
		shell.ErrTimeout:         "timeout",
		context.DeadlineExceeded: "timeout",
		shell.ErrClosed:          "closed",
		sshdial.ErrHandshake:     "handshake",
		driver.ErrIncomplete:     "incomplete",
		driver.ErrDeviceError:    "device-error",
		driver.ErrEmpty:          "empty",
		runner.ErrShrunk:         "shrunk",
		inventory.ErrCredential:  "credential",
		errors.New("unexpected"): "error",
	}
	for err, want := range cases {
		wrapped := fmt.Errorf("running-config: %w", err)
		if got := runner.Reason(wrapped); got != want {
			t.Errorf("Reason(%v) = %q, want %q", err, got, want)
		}
	}
	// A handshake cut short by the deadline is a timeout, not a handshake problem.
	if got := runner.Reason(fmt.Errorf("%w: x: %w", sshdial.ErrHandshake, context.DeadlineExceeded)); got != "timeout" {
		t.Errorf("handshake deadline = %q", got)
	}
}

// A collector that ignores its deadline still fails the device.
func TestRunnerEnforcesDeviceTimeout(t *testing.T) {
	remote := newRemote(t)
	devs := devices("slow")
	devs[0].Timeout = inventory.Duration(20 * time.Millisecond)
	c := collectorFunc(func(ctx context.Context, _ inventory.Device) (map[string][]byte, error) {
		time.Sleep(60 * time.Millisecond)
		return map[string][]byte{"running-config": bigConfig(1)}, nil
	})
	res, err := newRunner(t, remote, c, devs).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Failed) != 1 {
		t.Fatalf("slow device not failed: %+v", res)
	}
	st, _ := openStore(t, remote).ReadStatus()
	if st.Devices["slow"].Reason != "timeout" {
		t.Fatalf("status = %+v", st.Devices["slow"])
	}
}

func TestRunnerEmptyFilesFail(t *testing.T) {
	remote := newRemote(t)
	c := &fakeCollector{files: map[string]map[string][]byte{"sw1": {}}}
	res, err := newRunner(t, remote, c, devices("sw1")).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Failed) != 1 || len(res.Changed) != 0 {
		t.Fatalf("empty output accepted: %+v", res)
	}
}

func TestRunnerZeroConcurrencyStillRuns(t *testing.T) {
	remote := newRemote(t)
	c := &fakeCollector{files: map[string]map[string][]byte{
		"sw1": {"running-config": bigConfig(1)},
		"sw2": {"running-config": bigConfig(1)},
	}}
	r := newRunner(t, remote, c, devices("sw1", "sw2"))
	r.Concurrency = 0
	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changed) != 2 || c.peak != 1 {
		t.Fatalf("result %+v, peak %d", res, c.peak)
	}
}

// Without any change a failure-only run commits "Update collection status"
// and lists the failed devices.
func TestRunnerCommitMessageForFailuresOnly(t *testing.T) {
	remote := newRemote(t)
	c := &fakeCollector{errs: map[string]error{"sw1": sshdial.ErrAuth}}
	if _, err := newRunner(t, remote, c, devices("sw1")).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	msg := remoteCommits(t, remote)[0].Message
	if !strings.HasPrefix(msg, "Update collection status") || !strings.Contains(msg, "Failed: sw1") {
		t.Fatalf("commit message %q", msg)
	}
}

func TestRunnerCorruptStatusIsError(t *testing.T) {
	c := &fakeCollector{files: map[string]map[string][]byte{"sw1": {"running-config": bigConfig(1)}}}
	if _, err := newRunner(t, remoteWithStatus(t, "{"), c, devices("sw1")).Run(context.Background()); err == nil {
		t.Fatal("corrupt status.json accepted")
	}
}

// A file set that grows by a file and loses another counts as a change.
func TestRunnerReplacesFileSet(t *testing.T) {
	remote := newRemote(t)
	c := &fakeCollector{files: map[string]map[string][]byte{"sw1": {"a": bigConfig(5), "b": bigConfig(5)}}}
	if _, err := newRunner(t, remote, c, devices("sw1")).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.files["sw1"] = map[string][]byte{"a": bigConfig(5), "c": bigConfig(5)}
	res, err := newRunner(t, remote, c, devices("sw1")).Run(context.Background())
	if err != nil || len(res.Changed) != 1 {
		t.Fatalf("Run: %+v %v", res, err)
	}
	files, _ := openStore(t, remote).ReadDevice("sw1")
	if _, ok := files["b"]; ok || len(files) != 2 {
		t.Fatalf("files = %v", files)
	}
}

type collectorFunc func(context.Context, inventory.Device) (map[string][]byte, error)

func (f collectorFunc) Collect(ctx context.Context, dev inventory.Device) (map[string][]byte, error) {
	return f(ctx, dev)
}
