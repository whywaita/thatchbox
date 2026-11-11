// Package driver loads declarative device driver definitions and turns raw
// command output into the normalized, masked text that is committed.
package driver

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

const (
	// Masked replaces every secret value in committed output.
	Masked = "<masked>"
	// secretGroup is the named capture group a mask pattern must define.
	secretGroup = "secret"
	defFileExt  = ".yaml"
)

// Errors returned by Process. They never contain device output.
var (
	ErrIncomplete  = errors.New("output is incomplete: end marker not found")
	ErrDeviceError = errors.New("device reported an error for the command")
	ErrEmpty       = errors.New("output is empty")
)

// pemPrivateKey is masked for every driver as a safety net.
var pemPrivateKey = blockMask{
	begin: regexp.MustCompile(`^\s*-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\s*$`),
	end:   regexp.MustCompile(`^\s*-----END [A-Z0-9 ]*PRIVATE KEY-----\s*$`),
}

// Definition is the YAML form of a driver.
type Definition struct {
	Name       string       `yaml:"name"`
	Prompt     string       `yaml:"prompt"`
	Enable     *EnableDef   `yaml:"enable"`
	Setup      []string     `yaml:"setup"`
	Pager      *PagerDef    `yaml:"pager"`
	Error      string       `yaml:"error"`
	Drop       []string     `yaml:"drop"`
	Replace    []ReplaceDef `yaml:"replace"`
	Mask       []string     `yaml:"mask"`
	MaskBlocks []BlockDef   `yaml:"mask_blocks"`
	Outputs    []OutputDef  `yaml:"outputs"`
}

// EnableDef describes how to reach privileged mode.
type EnableDef struct {
	// When matches the login prompt that requires enable (e.g. ends with ">").
	When           string `yaml:"when"`
	Command        string `yaml:"command"`
	PasswordPrompt string `yaml:"password_prompt"`
}

// PagerDef describes how to answer a pager prompt that setup did not disable.
type PagerDef struct {
	Pattern string `yaml:"pattern"`
	Send    string `yaml:"send"`
}

// ReplaceDef rewrites matches of Pattern with With (regexp.Expand syntax).
type ReplaceDef struct {
	Pattern string `yaml:"pattern"`
	With    string `yaml:"with"`
}

// BlockDef masks every line strictly between a begin and an end line.
type BlockDef struct {
	Begin string `yaml:"begin"`
	End   string `yaml:"end"`
}

// OutputDef is one command whose output becomes one file.
type OutputDef struct {
	Path    string       `yaml:"path"`
	Command string       `yaml:"command"`
	End     string       `yaml:"end"`
	Drop    []string     `yaml:"drop"`
	Replace []ReplaceDef `yaml:"replace"`
	Mask    []string     `yaml:"mask"`
}

// Driver is a compiled definition.
type Driver struct {
	Name    string
	Prompt  *regexp.Regexp
	Enable  *Enable
	Setup   []string
	Pager   *Pager
	Outputs []Output

	errorRe    *regexp.Regexp
	drop       []*regexp.Regexp
	replace    []replacement
	mask       []*regexp.Regexp
	maskBlocks []blockMask
}

// Enable is the compiled form of EnableDef.
type Enable struct {
	When           *regexp.Regexp
	Command        string
	PasswordPrompt *regexp.Regexp
}

// Pager is the compiled form of PagerDef.
type Pager struct {
	Pattern *regexp.Regexp
	Send    string
}

// Output is the compiled form of OutputDef.
type Output struct {
	Path    string
	Command string

	end     *regexp.Regexp
	drop    []*regexp.Regexp
	replace []replacement
	mask    []*regexp.Regexp
}

type replacement struct {
	re   *regexp.Regexp
	with string
}

type blockMask struct {
	begin, end *regexp.Regexp
}

// Registry holds drivers by name.
type Registry struct {
	drivers map[string]*Driver
}

// Get returns the named driver.
func (r *Registry) Get(name string) (*Driver, bool) {
	d, ok := r.drivers[name]
	return d, ok
}

// Names returns the sorted driver names.
func (r *Registry) Names() []string {
	return slices.Sorted(maps.Keys(r.drivers))
}

// Load returns the built-in drivers, overridden or extended by every *.yaml
// file in dir when dir is not empty.
func Load(dir string) (*Registry, error) {
	reg := &Registry{drivers: map[string]*Driver{}}
	sub, err := fs.Sub(builtinFS, "builtin")
	if err != nil {
		return nil, err
	}
	if err := reg.loadFS(sub, "builtin"); err != nil {
		return nil, err
	}
	if dir == "" {
		return reg, nil
	}
	if err := reg.loadFS(os.DirFS(dir), dir); err != nil {
		return nil, err
	}
	return reg, nil
}

func (r *Registry) loadFS(fsys fs.FS, origin string) error {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return fmt.Errorf("read drivers from %s: %w", origin, err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != defFileExt {
			continue
		}
		data, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return fmt.Errorf("read driver %s/%s: %w", origin, e.Name(), err)
		}
		d, err := Parse(data)
		if err != nil {
			return fmt.Errorf("driver %s/%s: %w", origin, e.Name(), err)
		}
		r.drivers[d.Name] = d
	}
	return nil
}

// Parse compiles one YAML driver definition.
func Parse(data []byte) (*Driver, error) {
	var def Definition
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&def); err != nil {
		return nil, err
	}
	return Compile(def)
}

// Compile validates a definition and compiles its patterns.
func Compile(def Definition) (*Driver, error) {
	if def.Name == "" {
		return nil, errors.New("name is required")
	}
	if def.Prompt == "" {
		return nil, errors.New("prompt is required")
	}
	if len(def.Outputs) == 0 {
		return nil, errors.New("at least one output is required")
	}
	c := &compiler{}
	d := &Driver{
		Name:       def.Name,
		Prompt:     c.re("prompt", def.Prompt),
		Setup:      def.Setup,
		errorRe:    c.optional("error", def.Error),
		drop:       c.lines("drop", def.Drop),
		replace:    c.replacements("replace", def.Replace),
		mask:       c.masks("mask", def.Mask),
		maskBlocks: c.blocks(def.MaskBlocks),
	}
	if def.Enable != nil {
		if def.Enable.Command == "" {
			c.fail(errors.New("enable.command is required"))
		}
		d.Enable = &Enable{
			When:           c.re("enable.when", def.Enable.When),
			Command:        def.Enable.Command,
			PasswordPrompt: c.re("enable.password_prompt", def.Enable.PasswordPrompt),
		}
	}
	if def.Pager != nil {
		d.Pager = &Pager{Pattern: c.re("pager.pattern", def.Pager.Pattern), Send: def.Pager.Send}
	}
	seen := make(map[string]struct{}, len(def.Outputs))
	d.Outputs = make([]Output, 0, len(def.Outputs))
	for i, o := range def.Outputs {
		field := fmt.Sprintf("outputs[%d]", i)
		if err := ValidatePath(o.Path); err != nil {
			c.fail(fmt.Errorf("%s.path: %w", field, err))
		}
		if _, dup := seen[o.Path]; dup {
			c.fail(fmt.Errorf("%s.path: duplicate %q", field, o.Path))
		}
		seen[o.Path] = struct{}{}
		if o.Command == "" {
			c.fail(fmt.Errorf("%s.command is required", field))
		}
		d.Outputs = append(d.Outputs, Output{
			Path:    o.Path,
			Command: o.Command,
			end:     c.optional(field+".end", o.End),
			drop:    c.lines(field+".drop", o.Drop),
			replace: c.replacements(field+".replace", o.Replace),
			mask:    c.masks(field+".mask", o.Mask),
		})
	}
	if c.err != nil {
		return nil, c.err
	}
	return d, nil
}

// ValidatePath accepts a relative, clean, slash-separated path that stays
// inside its parent directory.
func ValidatePath(p string) error {
	switch {
	case p == "":
		return errors.New("must not be empty")
	case strings.Contains(p, `\`):
		return errors.New("must use forward slashes")
	case path.IsAbs(p) || !filepath.IsLocal(p):
		return errors.New("must be a relative path inside the device directory")
	case path.Clean(p) != p:
		return errors.New("must be a clean path")
	}
	return nil
}

// compiler accumulates the first compile error.
type compiler struct{ err error }

func (c *compiler) fail(err error) {
	if c.err == nil {
		c.err = err
	}
}

func (c *compiler) re(field, expr string) *regexp.Regexp {
	if expr == "" {
		c.fail(fmt.Errorf("%s is required", field))
		return nil
	}
	return c.optional(field, expr)
}

func (c *compiler) optional(field, expr string) *regexp.Regexp {
	if expr == "" {
		return nil
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		c.fail(fmt.Errorf("%s: %w", field, err))
		return nil
	}
	return re
}

func (c *compiler) lines(field string, exprs []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(exprs))
	for i, e := range exprs {
		out = append(out, c.re(fmt.Sprintf("%s[%d]", field, i), e))
	}
	return out
}

func (c *compiler) masks(field string, exprs []string) []*regexp.Regexp {
	out := c.lines(field, exprs)
	for i, re := range out {
		if re != nil && re.SubexpIndex(secretGroup) < 0 {
			c.fail(fmt.Errorf("%s[%d]: must define a (?P<%s>...) group", field, i, secretGroup))
		}
	}
	return out
}

func (c *compiler) replacements(field string, defs []ReplaceDef) []replacement {
	out := make([]replacement, 0, len(defs))
	for i, r := range defs {
		out = append(out, replacement{re: c.re(fmt.Sprintf("%s[%d].pattern", field, i), r.Pattern), with: r.With})
	}
	return out
}

func (c *compiler) blocks(defs []BlockDef) []blockMask {
	out := make([]blockMask, 0, len(defs)+1)
	for i, b := range defs {
		out = append(out, blockMask{
			begin: c.re(fmt.Sprintf("mask_blocks[%d].begin", i), b.Begin),
			end:   c.re(fmt.Sprintf("mask_blocks[%d].end", i), b.End),
		})
	}
	return append(out, pemPrivateKey)
}

// Process validates and normalizes the raw output of one command. The prompt
// and the echoed command must already be removed. Errors never include the
// output itself.
func (d *Driver) Process(o Output, raw string) (string, error) {
	lines := splitLines(raw)
	if d.errorRe != nil && slices.ContainsFunc(lines, d.errorRe.MatchString) {
		return "", ErrDeviceError
	}
	drop := slices.Concat(d.drop, o.drop)
	lines = slices.DeleteFunc(lines, func(l string) bool {
		return slices.ContainsFunc(drop, func(re *regexp.Regexp) bool { return re.MatchString(l) })
	})
	lines = trimBlankEdges(lines)
	if len(lines) == 0 {
		return "", ErrEmpty
	}
	if o.end != nil && !o.end.MatchString(lines[len(lines)-1]) {
		return "", ErrIncomplete
	}
	for _, r := range slices.Concat(d.replace, o.replace) {
		for i, l := range lines {
			lines[i] = r.re.ReplaceAllString(l, r.with)
		}
	}
	masks := slices.Concat(d.mask, o.mask)
	for i, l := range lines {
		for _, re := range masks {
			l = maskGroup(re, l)
		}
		lines[i] = l
	}
	for _, b := range d.maskBlocks {
		lines = b.apply(lines)
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// splitLines normalizes line endings and trailing whitespace.
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "")
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t")
	}
	return lines
}

func trimBlankEdges(lines []string) []string {
	start := 0
	for start < len(lines) && lines[start] == "" {
		start++
	}
	end := len(lines)
	for end > start && lines[end-1] == "" {
		end--
	}
	return lines[start:end]
}

// maskGroup replaces the "secret" group of every match in s.
func maskGroup(re *regexp.Regexp, s string) string {
	idx := re.SubexpIndex(secretGroup)
	matches := re.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		start, end := m[2*idx], m[2*idx+1]
		if start < 0 || start < last {
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString(Masked)
		last = end
	}
	b.WriteString(s[last:])
	return b.String()
}

func (b blockMask) apply(lines []string) []string {
	out := make([]string, 0, len(lines))
	inside := false
	for _, l := range lines {
		switch {
		case !inside && b.begin.MatchString(l):
			inside = true
			out = append(out, l)
		case inside && b.end.MatchString(l):
			inside = false
			out = append(out, Masked, l)
		case !inside:
			out = append(out, l)
		}
	}
	if inside {
		// An unterminated block is masked to the end rather than leaked.
		out = append(out, Masked)
	}
	return out
}
