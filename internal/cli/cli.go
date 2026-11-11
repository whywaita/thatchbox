// Package cli implements the thatchbox command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/skeema/knownhosts"

	"github.com/whywaita/thatchbox/internal/collect"
	"github.com/whywaita/thatchbox/internal/driver"
	"github.com/whywaita/thatchbox/internal/inventory"
	"github.com/whywaita/thatchbox/internal/runner"
	"github.com/whywaita/thatchbox/internal/store"
)

// Exit codes.
const (
	ExitOK             = 0
	ExitDeviceFailures = 1
	ExitFatal          = 2
)

const (
	defaultBranch      = "main"
	defaultAuthorName  = "thatchbox"
	defaultAuthorEmail = "thatchbox@localhost"
	gitSSHUser         = "git"
	workdirPattern     = "thatchbox-*"
)

// Version is set at build time.
var Version = "dev"

const usage = `usage: thatchbox <command> [flags]

commands:
  run       collect every enabled device and push the result
  validate  check the inventory and driver definitions
  drivers   list available drivers
  version   print the version
`

// Main runs the command line and returns the exit code.
func Main(args []string, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return ExitFatal
	}
	switch args[0] {
	case "run":
		return runCmd(args[1:], stderr)
	case "validate":
		return validateCmd(args[1:], stderr)
	case "drivers":
		return driversCmd(args[1:], stderr)
	case "version":
		fmt.Fprintln(stderr, Version)
		return ExitOK
	default:
		fmt.Fprint(stderr, usage)
		return ExitFatal
	}
}

type common struct {
	inventory string
	drivers   string
	logLevel  string
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.inventory, "inventory", "", "inventory YAML file (required)")
	fs.StringVar(&c.drivers, "drivers", "", "directory of additional or overriding driver YAML files")
	fs.StringVar(&c.logLevel, "log-level", "info", "debug, info, warn or error")
}

func (c *common) load() (*inventory.Inventory, *driver.Registry, error) {
	if c.inventory == "" {
		return nil, nil, errors.New("--inventory is required")
	}
	reg, err := driver.Load(c.drivers)
	if err != nil {
		return nil, nil, err
	}
	inv, err := inventory.Load(c.inventory, func(name string) bool {
		_, ok := reg.Get(name)
		return ok
	})
	if err != nil {
		return nil, nil, err
	}
	return inv, reg, nil
}

func (c *common) logger(w io.Writer) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(c.logLevel)); err != nil {
		return nil, err
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})), nil
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func runCmd(args []string, stderr io.Writer) int {
	var (
		c                        common
		repoURL, branch, workdir string
		gitKey, gitKnownHosts    string
		authorName, authorEmail  string
	)
	fs := newFlagSet("run", stderr)
	c.register(fs)
	fs.StringVar(&repoURL, "repo", "", "git remote to clone from and push to (required)")
	fs.StringVar(&branch, "branch", defaultBranch, "branch to update")
	fs.StringVar(&workdir, "workdir", "", "clone directory (default: a temporary directory removed afterwards)")
	fs.StringVar(&gitKey, "git-ssh-key", "", "private key for pushing over SSH (e.g. a deploy key)")
	fs.StringVar(&gitKnownHosts, "git-known-hosts", "", "known_hosts for the git remote (required with --git-ssh-key)")
	fs.StringVar(&authorName, "author-name", defaultAuthorName, "commit author name")
	fs.StringVar(&authorEmail, "author-email", defaultAuthorEmail, "commit author email")
	if err := fs.Parse(args); err != nil {
		return ExitFatal
	}
	log, err := c.logger(stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitFatal
	}
	fatal := func(msg string, err error) int {
		log.Error(msg, "error", err)
		return ExitFatal
	}
	if repoURL == "" {
		return fatal("invalid flags", errors.New("--repo is required"))
	}
	auth, err := gitAuth(gitKey, gitKnownHosts)
	if err != nil {
		return fatal("invalid flags", err)
	}
	inv, reg, err := c.load()
	if err != nil {
		return fatal("invalid configuration", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if workdir == "" {
		tmp, err := os.MkdirTemp("", workdirPattern)
		if err != nil {
			return fatal("create workdir", err)
		}
		defer os.RemoveAll(tmp)
		workdir = tmp
	}
	repo, err := store.Clone(ctx, store.Options{
		URL: repoURL, Dir: workdir, Branch: branch, Auth: auth,
		AuthorName: authorName, AuthorEmail: authorEmail,
	})
	if err != nil {
		return fatal("clone", err)
	}
	r := &runner.Runner{
		Devices:     inv.Devices,
		Concurrency: inv.Defaults.Concurrency,
		Collector:   &collect.Collector{Inventory: inv, Drivers: reg},
		Repo:        repo,
		Now:         time.Now,
		Logger:      log,
	}
	res, err := r.Run(ctx)
	if err != nil {
		return fatal("update repository", err)
	}
	if len(res.Failed) > 0 {
		log.Error("some devices failed", "failed", res.Failed)
		return ExitDeviceFailures
	}
	return ExitOK
}

func gitAuth(key, knownHostsFile string) (transport.AuthMethod, error) {
	if key == "" {
		return nil, nil
	}
	if knownHostsFile == "" {
		return nil, errors.New("--git-known-hosts is required with --git-ssh-key")
	}
	auth, err := gitssh.NewPublicKeysFromFile(gitSSHUser, key, "")
	if err != nil {
		return nil, errors.New("--git-ssh-key could not be loaded")
	}
	db, err := knownhosts.NewDB(knownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("--git-known-hosts: %w", err)
	}
	auth.HostKeyCallback = db.HostKeyCallback()
	return auth, nil
}

func validateCmd(args []string, stderr io.Writer) int {
	var c common
	fs := newFlagSet("validate", stderr)
	c.register(fs)
	if err := fs.Parse(args); err != nil {
		return ExitFatal
	}
	inv, _, err := c.load()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitFatal
	}
	fmt.Fprintf(stderr, "ok: %d devices\n", len(inv.Devices))
	return ExitOK
}

func driversCmd(args []string, stderr io.Writer) int {
	var dir string
	fs := newFlagSet("drivers", stderr)
	fs.StringVar(&dir, "drivers", "", "directory of additional or overriding driver YAML files")
	if err := fs.Parse(args); err != nil {
		return ExitFatal
	}
	reg, err := driver.Load(dir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitFatal
	}
	for _, n := range reg.Names() {
		fmt.Fprintln(stderr, n)
	}
	return ExitOK
}
