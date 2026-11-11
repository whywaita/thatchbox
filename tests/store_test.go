package tests

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/go-git/go-git/v5/plumbing/transport/file"

	"github.com/whywaita/thatchbox/internal/store"
)

func newRemote(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "remote.git")
	if _, err := git.PlainInit(dir, true); err != nil {
		t.Fatal(err)
	}
	return dir
}

func openStore(t *testing.T, remote string) *store.Repo {
	t.Helper()
	return openStoreDepth(t, remote, 0)
}

func openStoreDepth(t *testing.T, remote string, depth int) *store.Repo {
	t.Helper()
	r, err := store.Clone(context.Background(), store.Options{
		Depth:       depth,
		URL:         remote,
		Dir:         filepath.Join(t.TempDir(), "work"),
		Branch:      "main",
		AuthorName:  "thatchbox",
		AuthorEmail: "thatchbox@example.invalid",
	})
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	return r
}

func remoteCommits(t *testing.T, remote string) []*object.Commit {
	t.Helper()
	repo, err := git.PlainOpen(remote)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := repo.Reference("refs/heads/main", true)
	if err != nil {
		t.Fatalf("main branch: %v", err)
	}
	iter, err := repo.Log(&git.LogOptions{From: ref.Hash()})
	if err != nil {
		t.Fatal(err)
	}
	var out []*object.Commit
	_ = iter.ForEach(func(c *object.Commit) error {
		out = append(out, c)
		return nil
	})
	return out
}

func TestStoreRoundTripFromEmptyRemote(t *testing.T) {
	remote := newRemote(t)
	ctx := context.Background()

	r := openStore(t, remote)
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
	r2 := openStore(t, remote)
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

	r3 := openStore(t, remote)
	files, err = r3.ReadDevice("sw1")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || string(files["running-config"]) != "a2\n" {
		t.Fatalf("stale file not removed: %v", files)
	}
	if n := len(remoteCommits(t, remote)); n != 2 {
		t.Fatalf("remote has %d commits", n)
	}
}

// The container image has no git binary: local remotes must work without it.
func TestStoreWorksWithoutGitBinary(t *testing.T) {
	remote := newRemote(t)
	t.Setenv("PATH", t.TempDir())
	for i, content := range []string{"a\n", "b\n"} {
		r := openStore(t, remote)
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
	if n := len(remoteCommits(t, remote)); n != 2 {
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

	remote := newRemote(t)
	for i := range 3 {
		r := openStoreDepth(t, remote, store.ShallowDepth)
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
	if n := len(remoteCommits(t, remote)); n != 3 {
		t.Fatalf("remote has %d commits", n)
	}
}

func TestStoreNoChangeNoCommit(t *testing.T) {
	remote := newRemote(t)
	r := openStore(t, remote)
	if err := r.WriteDevice("sw1", map[string][]byte{"cfg": []byte("x\n")}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Commit("first"); err != nil {
		t.Fatal(err)
	}
	if err := r.Push(context.Background()); err != nil {
		t.Fatal(err)
	}
	r2 := openStore(t, remote)
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
	r := openStore(t, newRemote(t))
	if err := r.WriteDevice("../escape", map[string][]byte{"cfg": nil}); err == nil {
		t.Fatal("device name traversal accepted")
	}
	if err := r.WriteDevice("sw1", map[string][]byte{"../../escape": nil}); err == nil {
		t.Fatal("file path traversal accepted")
	}
}

func TestStoreStatusRoundTrip(t *testing.T) {
	remote := newRemote(t)
	r := openStore(t, remote)
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
	got, err := openStore(t, remote).ReadStatus()
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
