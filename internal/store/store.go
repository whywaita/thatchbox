// Package store keeps collected configurations in a git working tree:
// configs/<device>/<path> plus a status.json, cloned from and pushed to any
// git remote without invoking a shell or the git binary.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/go-git/go-git/v5/plumbing/transport/server"

	"github.com/whywaita/thatchbox/internal/driver"
)

const (
	configsDir = "configs"
	statusFile = "status.json"
	remoteName = "origin"
	fileScheme = "file"
	// ShallowDepth is the clone depth used for network remotes.
	ShallowDepth = 1
	dirPerm      = 0o755
	filePerm     = 0o644
	statusIndent = "  "
)

var deviceNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func init() {
	// go-git's default file transport runs git-upload-pack/git-receive-pack.
	// Serve local remotes in process so no git binary is ever needed.
	client.InstallProtocol(fileScheme, server.NewClient(server.DefaultLoader))
}

// Options configures Clone.
type Options struct {
	URL         string
	Dir         string
	Branch      string
	Auth        transport.AuthMethod
	AuthorName  string
	AuthorEmail string
	// Depth is the clone depth. Zero picks ShallowDepth for network remotes
	// and a full clone for local paths, whose in-process transport cannot
	// serve shallow clones.
	Depth int
}

func (o Options) depth() (int, error) {
	if o.Depth != 0 {
		return o.Depth, nil
	}
	ep, err := transport.NewEndpoint(o.URL)
	if err != nil {
		return 0, fmt.Errorf("remote url: %w", err)
	}
	if ep.Protocol == fileScheme {
		return 0, nil
	}
	return ShallowDepth, nil
}

// Repo is a working tree of the backup repository.
type Repo struct {
	opts Options
	repo *git.Repository
}

// Clone clones the branch (shallow for network remotes). An empty remote,
// or a remote without the branch, starts a new history.
func Clone(ctx context.Context, o Options) (*Repo, error) {
	depth, err := o.depth()
	if err != nil {
		return nil, err
	}
	branch := plumbing.NewBranchReferenceName(o.Branch)
	repo, err := git.PlainCloneContext(ctx, o.Dir, false, &git.CloneOptions{
		URL:           o.URL,
		Auth:          o.Auth,
		ReferenceName: branch,
		SingleBranch:  true,
		Depth:         depth,
		Tags:          git.NoTags,
	})
	switch {
	case err == nil:
		return &Repo{opts: o, repo: repo}, nil
	case errors.Is(err, transport.ErrEmptyRemoteRepository), isMissingBranch(err):
		if rmErr := os.RemoveAll(o.Dir); rmErr != nil {
			return nil, rmErr
		}
		return initRepo(o, branch)
	default:
		return nil, fmt.Errorf("clone: %w", err)
	}
}

func isMissingBranch(err error) bool {
	var noMatch git.NoMatchingRefSpecError
	return errors.As(err, &noMatch) || errors.Is(err, plumbing.ErrReferenceNotFound)
}

func initRepo(o Options, branch plumbing.ReferenceName) (*Repo, error) {
	repo, err := git.PlainInitWithOptions(o.Dir, &git.PlainInitOptions{
		InitOptions: git.InitOptions{DefaultBranch: branch},
	})
	if err != nil {
		return nil, fmt.Errorf("init: %w", err)
	}
	if _, err := repo.CreateRemote(&config.RemoteConfig{Name: remoteName, URLs: []string{o.URL}}); err != nil {
		return nil, fmt.Errorf("init remote: %w", err)
	}
	return &Repo{opts: o, repo: repo}, nil
}

func (r *Repo) deviceDir(name string) (string, error) {
	if !deviceNameRe.MatchString(name) {
		return "", fmt.Errorf("invalid device name %q", name)
	}
	return filepath.Join(r.opts.Dir, configsDir, name), nil
}

// ReadDevice returns the files previously stored for a device, keyed by
// slash-separated path. A device without files returns an empty map.
func (r *Repo) ReadDevice(name string) (map[string][]byte, error) {
	dir, err := r.deviceDir(name)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = b
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return files, nil
	}
	return files, err
}

// WriteDevice replaces the device directory with exactly files.
func (r *Repo) WriteDevice(name string, files map[string][]byte) error {
	dir, err := r.deviceDir(name)
	if err != nil {
		return err
	}
	for p := range files {
		if err := driver.ValidatePath(p); err != nil {
			return fmt.Errorf("file %q: %w", p, err)
		}
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	for p, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(path.Clean(p)))
		if err := os.MkdirAll(filepath.Dir(full), dirPerm); err != nil {
			return err
		}
		if err := os.WriteFile(full, content, filePerm); err != nil {
			return err
		}
	}
	return nil
}

// Dirty reports whether the working tree differs from HEAD.
func (r *Repo) Dirty() (bool, error) {
	w, err := r.repo.Worktree()
	if err != nil {
		return false, err
	}
	st, err := w.Status()
	if err != nil {
		return false, err
	}
	return !st.IsClean(), nil
}

// Commit stages everything and commits when something changed.
func (r *Repo) Commit(message string) (bool, error) {
	dirty, err := r.Dirty()
	if err != nil || !dirty {
		return false, err
	}
	w, err := r.repo.Worktree()
	if err != nil {
		return false, err
	}
	if err := w.AddWithOptions(&git.AddOptions{All: true}); err != nil {
		return false, fmt.Errorf("stage: %w", err)
	}
	sig := &object.Signature{Name: r.opts.AuthorName, Email: r.opts.AuthorEmail, When: time.Now()}
	if _, err := w.Commit(message, &git.CommitOptions{Author: sig, Committer: sig}); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return true, nil
}

// Push pushes the branch. A remote that moved meanwhile is an error.
func (r *Repo) Push(ctx context.Context) error {
	ref := plumbing.NewBranchReferenceName(r.opts.Branch)
	err := r.repo.PushContext(ctx, &git.PushOptions{
		RemoteName: remoteName,
		Auth:       r.opts.Auth,
		RefSpecs:   []config.RefSpec{config.RefSpec(ref + ":" + ref)},
	})
	if errors.Is(err, git.NoErrAlreadyUpToDate) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("push: %w", err)
	}
	return nil
}

// State of a device's last collection.
type State string

// States.
const (
	StateOK     State = "ok"
	StateFailed State = "failed"
)

// DeviceStatus is the recorded result for one device.
type DeviceStatus struct {
	Driver      string     `json:"driver"`
	State       State      `json:"state"`
	Reason      string     `json:"reason,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	LastFailure *time.Time `json:"last_failure,omitempty"`
}

// Status is the content of status.json.
type Status struct {
	Devices map[string]DeviceStatus `json:"devices"`
}

// Equivalent reports whether a and b differ only in timestamps.
func (a Status) Equivalent(b Status) bool {
	return maps.EqualFunc(a.Devices, b.Devices, func(x, y DeviceStatus) bool {
		return x.Driver == y.Driver && x.State == y.State && x.Reason == y.Reason
	})
}

// ReadStatus returns status.json, or an empty status when absent.
func (r *Repo) ReadStatus() (Status, error) {
	st := Status{Devices: map[string]DeviceStatus{}}
	b, err := os.ReadFile(filepath.Join(r.opts.Dir, statusFile))
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("parse %s: %w", statusFile, err)
	}
	if st.Devices == nil {
		st.Devices = map[string]DeviceStatus{}
	}
	return st, nil
}

// WriteStatus writes status.json.
func (r *Repo) WriteStatus(st Status) error {
	b, err := json.MarshalIndent(st, "", statusIndent)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(r.opts.Dir, statusFile), append(b, '\n'), filePerm)
}
