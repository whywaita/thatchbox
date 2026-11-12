package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/whywaita/thatchbox/internal/store"
	"github.com/whywaita/thatchbox/internal/testutil"
)

// A remote with history but without the branch starts that branch afresh
// and leaves the other branch alone.
func TestStoreMissingBranchStartsNewHistory(t *testing.T) {
	remote := testutil.NewRemote(t)
	main := testutil.OpenStore(t, remote)
	if err := main.WriteDevice("sw1", map[string][]byte{"cfg": []byte("main\n")}); err != nil {
		t.Fatal(err)
	}
	if _, err := main.Commit("main"); err != nil {
		t.Fatal(err)
	}
	if err := main.Push(context.Background()); err != nil {
		t.Fatal(err)
	}

	other := testutil.StoreAt(t, remote, filepath.Join(t.TempDir(), "work"), "backups")
	if files, err := other.ReadDevice("sw1"); err != nil || len(files) != 0 {
		t.Fatalf("new branch is not empty: %v %v", files, err)
	}
	if err := other.WriteDevice("sw2", map[string][]byte{"cfg": []byte("other\n")}); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Commit("other"); err != nil {
		t.Fatal(err)
	}
	if err := other.Push(context.Background()); err != nil {
		t.Fatalf("push new branch: %v", err)
	}

	again := testutil.StoreAt(t, remote, filepath.Join(t.TempDir(), "work"), "backups")
	if files, _ := again.ReadDevice("sw2"); string(files["cfg"]) != "other\n" {
		t.Fatalf("branch not pushed: %v", files)
	}
	if files, _ := testutil.OpenStore(t, remote).ReadDevice("sw1"); string(files["cfg"]) != "main\n" {
		t.Fatalf("main changed: %v", files)
	}
}

func TestStoreCloneErrors(t *testing.T) {
	for name, url := range map[string]string{
		"missing local remote": filepath.Join(t.TempDir(), "nope.git"),
		"invalid url":          "ssh://[::1",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := store.Clone(context.Background(), store.Options{URL: url, Dir: filepath.Join(t.TempDir(), "w"), Branch: "main"})
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// A push loses when the remote moved since the clone; the next run starts
// from the new remote state.
func TestStorePushRejectsMovedRemote(t *testing.T) {
	remote := testutil.RemoteWithStatus(t, `{"devices":{}}`+"\n")
	a := testutil.OpenStore(t, remote)
	b := testutil.OpenStore(t, remote)
	for i, r := range []*store.Repo{a, b} {
		if err := r.WriteDevice("sw1", map[string][]byte{"cfg": []byte{byte('a' + i), '\n'}}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Commit("run"); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Push(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := b.Push(context.Background()); err == nil {
		t.Fatal("non-fast-forward push accepted")
	}
}

func TestStorePushWithoutChangesIsNoop(t *testing.T) {
	r := testutil.OpenStore(t, testutil.RemoteWithStatus(t, `{"devices":{}}`+"\n"))
	if err := r.Push(context.Background()); err != nil {
		t.Fatalf("up-to-date push: %v", err)
	}
}

func TestStoreReadStatus(t *testing.T) {
	cases := map[string]struct {
		content string
		devices int
		wantErr bool
	}{
		"corrupt":      {content: "{", wantErr: true},
		"null devices": {content: `{"devices": null}`},
		"one device":   {content: `{"devices": {"sw1": {"driver": "junos", "state": "failed", "reason": "auth"}}}`, devices: 1},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			st, err := testutil.OpenStore(t, testutil.RemoteWithStatus(t, c.content)).ReadStatus()
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v", err)
			}
			if c.wantErr {
				return
			}
			if st.Devices == nil || len(st.Devices) != c.devices {
				t.Fatalf("devices = %v", st.Devices)
			}
		})
	}
}

func TestStoreReadDeviceRejectsUnsafeName(t *testing.T) {
	r := testutil.OpenStore(t, testutil.NewRemote(t))
	for _, name := range []string{"", "../x", ".hidden", "a/b"} {
		if _, err := r.ReadDevice(name); err == nil {
			t.Errorf("ReadDevice(%q) accepted", name)
		}
	}
}

func TestStoreWriteDeviceRejectsBadPathsBeforeTouchingFiles(t *testing.T) {
	r := testutil.OpenStore(t, testutil.NewRemote(t))
	if err := r.WriteDevice("sw1", map[string][]byte{"cfg": []byte("keep\n")}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"", "/abs", "a/../b", `a\b`, "./a"} {
		if err := r.WriteDevice("sw1", map[string][]byte{"ok": []byte("x\n"), p: []byte("x\n")}); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
	files, err := r.ReadDevice("sw1")
	if err != nil || string(files["cfg"]) != "keep\n" || len(files) != 1 {
		t.Fatalf("rejected write changed files: %v %v", files, err)
	}
}

func TestStatusEquivalent(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	base := map[string]store.DeviceStatus{
		"sw1": {Driver: "cisco_ios", State: store.StateOK, LastSuccess: &t1},
		"sw2": {Driver: "junos", State: store.StateFailed, Reason: "auth", LastFailure: &t1},
	}
	with := func(name string, f func(*store.DeviceStatus)) store.Status {
		devs := map[string]store.DeviceStatus{}
		for k, v := range base {
			devs[k] = v
		}
		d := devs[name]
		f(&d)
		devs[name] = d
		return store.Status{Devices: devs}
	}
	a := store.Status{Devices: base}
	cases := map[string]struct {
		b    store.Status
		want bool
	}{
		"same":           {with("sw1", func(*store.DeviceStatus) {}), true},
		"timestamp only": {with("sw2", func(d *store.DeviceStatus) { d.LastFailure = nil }), true},
		"driver":         {with("sw1", func(d *store.DeviceStatus) { d.Driver = "nec_ix" }), false},
		"reason":         {with("sw2", func(d *store.DeviceStatus) { d.Reason = "timeout" }), false},
		"state":          {with("sw1", func(d *store.DeviceStatus) { d.State = store.StateFailed }), false},
		"renamed device": {store.Status{Devices: map[string]store.DeviceStatus{"sw1": base["sw1"], "sw3": base["sw2"]}}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := a.Equivalent(c.b); got != c.want {
				t.Fatalf("Equivalent = %v", got)
			}
			if got := c.b.Equivalent(a); got != c.want {
				t.Fatalf("reverse Equivalent = %v", got)
			}
		})
	}
}

func TestStoreCommitWithoutChanges(t *testing.T) {
	r := testutil.OpenStore(t, testutil.NewRemote(t))
	committed, err := r.Commit("nothing")
	if err != nil || committed {
		t.Fatalf("empty commit: %v %v", committed, err)
	}
	if dirty, err := r.Dirty(); err != nil || dirty {
		t.Fatalf("fresh clone dirty: %v %v", dirty, err)
	}
}
