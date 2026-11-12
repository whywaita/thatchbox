package store_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/go-git/go-git/v5/plumbing/transport/file"

	"github.com/whywaita/thatchbox/internal/store"
	"github.com/whywaita/thatchbox/internal/testutil"
)

func TestStoreRoundTripFromEmptyRemote(t *testing.T) {
	remote := testutil.NewRemote(t)
	ctx := context.Background()

	r := testutil.OpenStore(t, remote)
	if files, err := r.ReadDevice("sw1"); err != nil || len(files) != 0 {
		t.Fatalf("empty remote: %v %v", files, err)
	}
	if err := r.WriteDevice("sw1", map[string][]byte{"running-config": []byte("a\n"), "sub/dir": []byte("b\n")}); err != nil {
		t.Fatal(err)
	}
	committed, err := r.Commit("first")
	if err != nil || !committed {
		t.Fatalf("Commit: %v %v", committed, err)
	}
	if err := r.Push(ctx); err != nil {
		t.Fatalf("Push: %v", err)
	}

	// Second run: shallow clone of existing history.
	r2 := testutil.OpenStore(t, remote)
	files, err := r2.ReadDevice("sw1")
	if err != nil {
		t.Fatal(err)
	}
	if string(files["running-config"]) != "a\n" || string(files["sub/dir"]) != "b\n" {
		t.Fatalf("unexpected files: %v", files)
	}
	if err := r2.WriteDevice("sw1", map[string][]byte{"running-config": []byte("a2\n")}); err != nil {
		t.Fatal(err)
	}
	if committed, err := r2.Commit("second"); err != nil || !committed {
		t.Fatalf("Commit: %v %v", committed, err)
	}
	if err := r2.Push(ctx); err != nil {
		t.Fatalf("Push from shallow clone: %v", err)
	}

	r3 := testutil.OpenStore(t, remote)
	files, err = r3.ReadDevice("sw1")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || string(files["running-config"]) != "a2\n" {
		t.Fatalf("stale file not removed: %v", files)
	}
	if n := len(testutil.RemoteCommits(t, remote)); n != 2 {
		t.Fatalf("remote has %d commits", n)
	}
}

// The container image has no git binary: local remotes must work without it.
func TestStoreWorksWithoutGitBinary(t *testing.T) {
	remote := testutil.NewRemote(t)
	t.Setenv("PATH", t.TempDir())
	for i, content := range []string{"a\n", "b\n"} {
		r := testutil.OpenStore(t, remote)
		if err := r.WriteDevice("sw1", map[string][]byte{"cfg": []byte(content)}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Commit("run"); err != nil {
			t.Fatal(err)
		}
		if err := r.Push(context.Background()); err != nil {
			t.Fatalf("push %d without git binary: %v", i, err)
		}
	}
	if n := len(testutil.RemoteCommits(t, remote)); n != 2 {
		t.Fatalf("remote has %d commits", n)
	}
}

// Network remotes are cloned with depth 1. The in-process file transport
// cannot serve shallow clones, so this exercises the shallow clone, commit
// and push path through the external transport when its binary exists.
func TestStoreShallowClonePush(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	orig := client.Protocols["file"]
	client.InstallProtocol("file", file.DefaultClient)
	t.Cleanup(func() { client.InstallProtocol("file", orig) })

	remote := testutil.NewRemote(t)
	for i := range 3 {
		r := testutil.OpenStoreDepth(t, remote, store.ShallowDepth)
		if err := r.WriteDevice("sw1", map[string][]byte{"cfg": []byte(strings.Repeat("x", i+1))}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Commit("run"); err != nil {
			t.Fatal(err)
		}
		if err := r.Push(context.Background()); err != nil {
			t.Fatalf("push %d from shallow clone: %v", i, err)
		}
	}
	if n := len(testutil.RemoteCommits(t, remote)); n != 3 {
		t.Fatalf("remote has %d commits", n)
	}
}

func TestStoreNoChangeNoCommit(t *testing.T) {
	remote := testutil.NewRemote(t)
	r := testutil.OpenStore(t, remote)
	if err := r.WriteDevice("sw1", map[string][]byte{"cfg": []byte("x\n")}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Commit("first"); err != nil {
		t.Fatal(err)
	}
	if err := r.Push(context.Background()); err != nil {
		t.Fatal(err)
	}
	r2 := testutil.OpenStore(t, remote)
	if err := r2.WriteDevice("sw1", map[string][]byte{"cfg": []byte("x\n")}); err != nil {
		t.Fatal(err)
	}
	if dirty, err := r2.Dirty(); err != nil || dirty {
		t.Fatalf("Dirty: %v %v", dirty, err)
	}
	if committed, err := r2.Commit("noop"); err != nil || committed {
		t.Fatalf("expected no commit: %v %v", committed, err)
	}
}

func TestStoreRejectsUnsafeNames(t *testing.T) {
	r := testutil.OpenStore(t, testutil.NewRemote(t))
	if err := r.WriteDevice("../escape", map[string][]byte{"cfg": nil}); err == nil {
		t.Fatal("device name traversal accepted")
	}
	if err := r.WriteDevice("sw1", map[string][]byte{"../../escape": nil}); err == nil {
		t.Fatal("file path traversal accepted")
	}
}

func TestStoreStatusRoundTrip(t *testing.T) {
	remote := testutil.NewRemote(t)
	r := testutil.OpenStore(t, remote)
	st, err := r.ReadStatus()
	if err != nil || len(st.Devices) != 0 {
		t.Fatalf("empty status: %v %v", st, err)
	}
	now := time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)
	st.Devices["sw1"] = store.DeviceStatus{Driver: "cisco_ios", State: store.StateOK, LastSuccess: &now}
	if err := r.WriteStatus(st); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Commit("status"); err != nil {
		t.Fatal(err)
	}
	if err := r.Push(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := testutil.OpenStore(t, remote).ReadStatus()
	if err != nil {
		t.Fatal(err)
	}
	if d := got.Devices["sw1"]; d.State != store.StateOK || !d.LastSuccess.Equal(now) {
		t.Fatalf("status lost: %+v", d)
	}
}

func TestStatusEquivalentIgnoresTimestamps(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)
	a := store.Status{Devices: map[string]store.DeviceStatus{"sw1": {Driver: "x", State: store.StateOK, LastSuccess: &t1}}}
	b := store.Status{Devices: map[string]store.DeviceStatus{"sw1": {Driver: "x", State: store.StateOK, LastSuccess: &t2}}}
	if !a.Equivalent(b) {
		t.Fatal("timestamps only should be equivalent")
	}
	c := store.Status{Devices: map[string]store.DeviceStatus{"sw1": {Driver: "x", State: store.StateFailed, Reason: "timeout", LastSuccess: &t1}}}
	if a.Equivalent(c) {
		t.Fatal("state change must not be equivalent")
	}
	d := store.Status{Devices: map[string]store.DeviceStatus{}}
	if a.Equivalent(d) {
		t.Fatal("device set change must not be equivalent")
	}
}
