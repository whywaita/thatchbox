// Package runner performs one collection run: collect every enabled device
// in parallel, validate, write, record status, commit and push.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/whywaita/thatchbox/internal/driver"
	"github.com/whywaita/thatchbox/internal/inventory"
	"github.com/whywaita/thatchbox/internal/shell"
	"github.com/whywaita/thatchbox/internal/sshdial"
	"github.com/whywaita/thatchbox/internal/store"
	"github.com/whywaita/thatchbox/internal/telnet"
)

// ErrShrunk means the new output is much smaller than the stored one,
// which usually indicates a truncated collection.
var ErrShrunk = errors.New("output shrank below min_size_ratio of the previous version")

// Collector fetches the files of one device.
type Collector interface {
	Collect(ctx context.Context, dev inventory.Device) (map[string][]byte, error)
}

// Runner holds the dependencies of a run.
type Runner struct {
	Devices     []inventory.Device
	Concurrency int
	Collector   Collector
	Repo        *store.Repo
	Now         func() time.Time
	Logger      *slog.Logger
}

// Result summarizes a run.
type Result struct {
	Changed   []string
	Failed    []string
	Committed bool
}

type outcome struct {
	dev   inventory.Device
	files map[string][]byte
	err   error
}

// Run executes the run. Device failures are reported in Result; an error is
// returned only when the repository could not be updated.
func (r *Runner) Run(ctx context.Context) (Result, error) {
	var res Result
	prev, err := r.Repo.ReadStatus()
	if err != nil {
		return res, err
	}
	outcomes := r.collectAll(ctx)
	next := store.Status{Devices: maps.Clone(prev.Devices)}
	now := r.Now().UTC()
	for _, o := range outcomes {
		st := next.Devices[o.dev.Name]
		st.Driver = o.dev.Driver
		if o.err == nil {
			o.err = r.save(o, &res)
		}
		if o.err != nil {
			reason := Reason(o.err)
			r.Logger.Warn("collection failed", "device", o.dev.Name, "reason", reason, "error", o.err)
			res.Failed = append(res.Failed, o.dev.Name)
			st.State, st.Reason, st.LastFailure = store.StateFailed, reason, &now
		} else {
			st.State, st.Reason, st.LastSuccess = store.StateOK, "", &now
		}
		next.Devices[o.dev.Name] = st
	}
	dirty, err := r.Repo.Dirty()
	if err != nil {
		return res, err
	}
	if !dirty && prev.Equivalent(next) {
		r.Logger.Info("no changes", "failed", len(res.Failed))
		return res, nil
	}
	if err := r.Repo.WriteStatus(next); err != nil {
		return res, err
	}
	if res.Committed, err = r.Repo.Commit(commitMessage(res)); err != nil {
		return res, err
	}
	if err := r.Repo.Push(ctx); err != nil {
		return res, err
	}
	r.Logger.Info("pushed", "changed", res.Changed, "failed", res.Failed)
	return res, nil
}

func (r *Runner) collectAll(ctx context.Context) []outcome {
	enabled := slices.DeleteFunc(slices.Clone(r.Devices), func(d inventory.Device) bool { return !d.IsEnabled() })
	outcomes := make([]outcome, len(enabled))
	sem := make(chan struct{}, max(r.Concurrency, 1))
	var wg sync.WaitGroup
	for i, dev := range enabled {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			dctx, cancel := context.WithTimeout(ctx, time.Duration(dev.Timeout))
			defer cancel()
			start := time.Now()
			files, err := r.Collector.Collect(dctx, dev)
			if err == nil && dctx.Err() != nil {
				err = dctx.Err()
			}
			r.Logger.Debug("collected", "device", dev.Name, "elapsed", time.Since(start), "ok", err == nil)
			outcomes[i] = outcome{dev: dev, files: files, err: err}
		})
	}
	wg.Wait()
	return outcomes
}

// save validates o against the stored version and writes it.
func (r *Runner) save(o outcome, res *Result) error {
	if len(o.files) == 0 {
		return driver.ErrEmpty
	}
	old, err := r.Repo.ReadDevice(o.dev.Name)
	if err != nil {
		return err
	}
	ratio := inventory.DefaultMinSizeRatio
	if o.dev.MinSizeRatio != nil {
		ratio = *o.dev.MinSizeRatio
	}
	if before, after := totalSize(old), totalSize(o.files); before > 0 && float64(after) < ratio*float64(before) {
		return fmt.Errorf("%w (%d -> %d bytes)", ErrShrunk, before, after)
	}
	if maps.EqualFunc(old, o.files, bytes.Equal) {
		return nil
	}
	if err := r.Repo.WriteDevice(o.dev.Name, o.files); err != nil {
		return err
	}
	res.Changed = append(res.Changed, o.dev.Name)
	return nil
}

func totalSize(files map[string][]byte) int {
	n := 0
	for _, b := range files {
		n += len(b)
	}
	return n
}

func commitMessage(res Result) string {
	var b strings.Builder
	switch {
	case len(res.Changed) > 0:
		fmt.Fprintf(&b, "Update %s", strings.Join(res.Changed, ", "))
	default:
		b.WriteString("Update collection status")
	}
	if len(res.Failed) > 0 {
		fmt.Fprintf(&b, "\n\nFailed: %s", strings.Join(res.Failed, ", "))
	}
	return b.String() + "\n"
}

// Reason maps an error to a short, output-free category for status.json.
func Reason(err error) string {
	reasons := []struct {
		target error
		reason string
	}{
		{sshdial.ErrHostKey, "host-key"},
		{sshdial.ErrAuth, "auth"},
		{shell.ErrLogin, "auth"},
		{sshdial.ErrConnect, "connect"},
		{telnet.ErrConnect, "connect"},
		{sshdial.ErrSession, "session"},
		{shell.ErrEnable, "enable"},
		{shell.ErrTimeout, "timeout"},
		{context.DeadlineExceeded, "timeout"},
		{shell.ErrClosed, "closed"},
		{sshdial.ErrHandshake, "handshake"},
		{driver.ErrIncomplete, "incomplete"},
		{driver.ErrDeviceError, "device-error"},
		{driver.ErrEmpty, "empty"},
		{ErrShrunk, "shrunk"},
		{inventory.ErrCredential, "credential"},
	}
	for _, r := range reasons {
		if errors.Is(err, r.target) {
			return r.reason
		}
	}
	return "error"
}
