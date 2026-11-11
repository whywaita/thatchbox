package tests

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whywaita/thatchbox/internal/inventory"
	"github.com/whywaita/thatchbox/internal/runner"
	"github.com/whywaita/thatchbox/internal/shell"
	"github.com/whywaita/thatchbox/internal/store"
)

// fakeCollector returns canned files per device.
type fakeCollector struct {
	mu      sync.Mutex
	files   map[string]map[string][]byte
	errs    map[string]error
	calls   []string
	running int
	peak    int
}

func (f *fakeCollector) Collect(ctx context.Context, dev inventory.Device) (map[string][]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, dev.Name)
	f.running++
	f.peak = max(f.peak, f.running)
	f.mu.Unlock()
	time.Sleep(10 * time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.running--
	if err := f.errs[dev.Name]; err != nil {
		return nil, err
	}
	return f.files[dev.Name], nil
}

func devices(names ...string) []inventory.Device {
	ratio := inventory.DefaultMinSizeRatio
	out := make([]inventory.Device, 0, len(names))
	for _, n := range names {
		out = append(out, inventory.Device{Name: n, Driver: "cisco_ios", MinSizeRatio: &ratio, Timeout: inventory.Duration(time.Second)})
	}
	return out
}

func newRunner(t *testing.T, remote string, c runner.Collector, devs []inventory.Device) *runner.Runner {
	t.Helper()
	return &runner.Runner{
		Devices:     devs,
		Concurrency: 2,
		Collector:   c,
		Repo:        openStore(t, remote),
		Now:         func() time.Time { return time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC) },
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func bigConfig(n int) []byte {
	return []byte(strings.Repeat("interface x\n", n) + "end\n")
}

func TestRunnerPartialFailureStillPushes(t *testing.T) {
	remote := newRemote(t)
	c := &fakeCollector{
		files: map[string]map[string][]byte{
			"sw1": {"running-config": bigConfig(10)},
			"sw2": {"running-config": bigConfig(20)},
		},
		errs: map[string]error{"r1": shell.ErrTimeout},
	}
	res, err := newRunner(t, remote, c, devices("sw1", "sw2", "r1")).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Committed || len(res.Failed) != 1 || res.Failed[0] != "r1" {
		t.Fatalf("unexpected result %+v", res)
	}
	repo := openStore(t, remote)
	files, _ := repo.ReadDevice("sw2")
	if string(files["running-config"]) != string(bigConfig(20)) {
		t.Fatalf("sw2 not pushed: %v", files)
	}
	st, _ := repo.ReadStatus()
	if st.Devices["r1"].State != store.StateFailed || st.Devices["r1"].Reason != "timeout" {
		t.Fatalf("r1 status: %+v", st.Devices["r1"])
	}
	if st.Devices["sw1"].State != store.StateOK || st.Devices["sw1"].LastSuccess == nil {
		t.Fatalf("sw1 status: %+v", st.Devices["sw1"])
	}
	if c.peak > 2 {
		t.Fatalf("concurrency limit exceeded: %d", c.peak)
	}
}

func TestRunnerSkipsEmptyCommits(t *testing.T) {
	remote := newRemote(t)
	c := &fakeCollector{files: map[string]map[string][]byte{"sw1": {"running-config": bigConfig(10)}}}
	if _, err := newRunner(t, remote, c, devices("sw1")).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := newRunner(t, remote, c, devices("sw1"))
	r.Now = func() time.Time { return time.Date(2026, 11, 11, 4, 0, 0, 0, time.UTC) }
	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Committed {
		t.Fatal("unchanged run must not commit")
	}
	if n := len(remoteCommits(t, remote)); n != 1 {
		t.Fatalf("remote has %d commits", n)
	}
}

func TestRunnerRejectsShrunkOutputAndKeepsPrevious(t *testing.T) {
	remote := newRemote(t)
	c := &fakeCollector{files: map[string]map[string][]byte{"sw1": {"running-config": bigConfig(100)}}}
	if _, err := newRunner(t, remote, c, devices("sw1")).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.files["sw1"] = map[string][]byte{"running-config": bigConfig(10)}
	res, err := newRunner(t, remote, c, devices("sw1")).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Failed) != 1 {
		t.Fatalf("shrink not detected: %+v", res)
	}
	repo := openStore(t, remote)
	files, _ := repo.ReadDevice("sw1")
	if string(files["running-config"]) != string(bigConfig(100)) {
		t.Fatal("previous config was overwritten")
	}
	st, _ := repo.ReadStatus()
	if st.Devices["sw1"].Reason != "shrunk" {
		t.Fatalf("status: %+v", st.Devices["sw1"])
	}
}

func TestRunnerCommitsStateTransitionOnly(t *testing.T) {
	remote := newRemote(t)
	c := &fakeCollector{files: map[string]map[string][]byte{"sw1": {"running-config": bigConfig(10)}}}
	if _, err := newRunner(t, remote, c, devices("sw1")).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.errs = map[string]error{"sw1": errors.New("boom")}
	res, err := newRunner(t, remote, c, devices("sw1")).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Committed {
		t.Fatal("ok -> failed transition must be committed")
	}
	// Repeated identical failure: no new commit.
	res, err = newRunner(t, remote, c, devices("sw1")).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Committed {
		t.Fatal("repeated failure must not commit")
	}
	st, _ := openStore(t, remote).ReadStatus()
	if st.Devices["sw1"].LastSuccess == nil {
		t.Fatal("last_success lost on failure")
	}
}

func TestRunnerSkipsDisabledDevices(t *testing.T) {
	remote := newRemote(t)
	c := &fakeCollector{files: map[string]map[string][]byte{"sw1": {"running-config": bigConfig(10)}}}
	devs := devices("sw1", "off")
	disabled := false
	devs[1].Enabled = &disabled
	res, err := newRunner(t, remote, c, devs).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Failed) != 0 || len(c.calls) != 1 {
		t.Fatalf("disabled device collected: %v %+v", c.calls, res)
	}
}

func TestRunnerReportsChangedDevicesInCommit(t *testing.T) {
	remote := newRemote(t)
	c := &fakeCollector{files: map[string]map[string][]byte{
		"sw1": {"running-config": bigConfig(10)},
		"sw2": {"running-config": bigConfig(10)},
	}}
	if _, err := newRunner(t, remote, c, devices("sw1", "sw2")).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.files["sw2"] = map[string][]byte{"running-config": bigConfig(11)}
	res, err := newRunner(t, remote, c, devices("sw1", "sw2")).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changed) != 1 || res.Changed[0] != "sw2" {
		t.Fatalf("changed = %v", res.Changed)
	}
	msg := remoteCommits(t, remote)[0].Message
	if !strings.Contains(msg, "sw2") || strings.Contains(msg, "sw1") {
		t.Fatalf("commit message %q", msg)
	}
}
