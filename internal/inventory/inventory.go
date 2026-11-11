// Package inventory loads the device list and credential references.
package inventory

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Defaults used when neither the inventory defaults nor a device set a value.
const (
	DefaultConcurrency  = 8
	DefaultTimeout      = 2 * time.Minute
	DefaultPort         = 22
	DefaultTelnetPort   = 23
	DefaultMinSizeRatio = 0.5
)

// Transports.
const (
	TransportSSH    = "ssh"
	TransportTelnet = "telnet"
)

// ErrCredential means a secret reference could not be resolved.
var ErrCredential = errors.New("credential unavailable")

// nameRe keeps device names safe as directory names.
var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Inventory is the whole configuration.
type Inventory struct {
	Defaults    Defaults              `yaml:"defaults"`
	Credentials map[string]Credential `yaml:"credentials"`
	JumpHosts   map[string]JumpHost   `yaml:"jump_hosts"`
	Devices     []Device              `yaml:"devices"`
}

// Defaults apply to every device that does not override them.
type Defaults struct {
	Concurrency  int      `yaml:"concurrency"`
	Timeout      Duration `yaml:"timeout"`
	Port         int      `yaml:"port"` // SSH port; telnet uses DefaultTelnetPort
	KnownHosts   string   `yaml:"known_hosts"`
	MinSizeRatio float64  `yaml:"min_size_ratio"`
	SSH          SSH      `yaml:"ssh"`
}

// Credential is a named login. Secret values are references only. SSH needs
// a username; telnet may use a password alone (a line password).
type Credential struct {
	Username   Secret `yaml:"username"`
	Password   Secret `yaml:"password"`
	PrivateKey Secret `yaml:"private_key"`
	// PrivateKeyPassphrase decrypts an encrypted PrivateKey.
	PrivateKeyPassphrase Secret `yaml:"private_key_passphrase"`
	EnablePassword       Secret `yaml:"enable_password"`
}

// JumpHost is an SSH bastion used to reach devices.
type JumpHost struct {
	Address    string `yaml:"address"`
	Port       int    `yaml:"port"`
	Credential string `yaml:"credential"`
	KnownHosts string `yaml:"known_hosts"`
	SSH        SSH    `yaml:"ssh"`
}

// Device is one network device.
type Device struct {
	Name         string   `yaml:"name"`
	Address      string   `yaml:"address"`
	Port         int      `yaml:"port"`
	Driver       string   `yaml:"driver"`
	Transport    string   `yaml:"transport"` // ssh (default) or telnet
	Credential   string   `yaml:"credential"`
	Enabled      *bool    `yaml:"enabled"`
	Jump         string   `yaml:"jump"`
	Timeout      Duration `yaml:"timeout"`
	KnownHosts   string   `yaml:"known_hosts"`
	MinSizeRatio *float64 `yaml:"min_size_ratio"`
	SSH          SSH      `yaml:"ssh"`
}

// SSH lists algorithm overrides. An entry starting with "+" is appended to
// the library defaults (e.g. "+ssh-rsa"); otherwise the list replaces them.
type SSH struct {
	KeyExchanges      []string `yaml:"kex"`
	Ciphers           []string `yaml:"ciphers"`
	MACs              []string `yaml:"macs"`
	HostKeyAlgorithms []string `yaml:"host_key_algorithms"`
}

// IsEnabled reports whether the device should be collected.
func (d Device) IsEnabled() bool { return d.Enabled == nil || *d.Enabled }

// Duration accepts Go duration strings such as "90s" or "5m".
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// Secret is a value read at run time from an environment variable or a
// file. A plain scalar is a literal, which is accepted only for usernames.
type Secret struct {
	Env     string `yaml:"env"`
	File    string `yaml:"file"`
	Literal string `yaml:"-"`
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *Secret) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		return n.Decode(&s.Literal)
	}
	type plain Secret
	var p plain
	if err := n.Decode(&p); err != nil {
		return err
	}
	*s = Secret(p)
	return nil
}

// IsZero reports whether no value is configured.
func (s Secret) IsZero() bool { return s == Secret{} }

// Resolve returns the value. File contents lose one trailing newline.
func (s Secret) Resolve() (string, error) {
	switch {
	case s.Env != "":
		v, ok := os.LookupEnv(s.Env)
		if !ok || v == "" {
			return "", fmt.Errorf("%w: environment variable %s is not set", ErrCredential, s.Env)
		}
		return v, nil
	case s.File != "":
		b, err := os.ReadFile(s.File)
		if err != nil {
			return "", fmt.Errorf("%w: read secret file: %w", ErrCredential, err)
		}
		return strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"), nil
	default:
		return s.Literal, nil
	}
}

func (s Secret) validate(field string, literalOK bool) error {
	if s.Env != "" && s.File != "" {
		return fmt.Errorf("%s: set only one of env and file", field)
	}
	if s.Literal != "" && !literalOK {
		return fmt.Errorf("%s: must be {env: NAME} or {file: PATH}, not a literal value", field)
	}
	return nil
}

// Load reads and validates an inventory. knownDriver reports whether a
// driver name exists.
func Load(path string, knownDriver func(string) bool) (*Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var inv Inventory
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&inv); err != nil {
		return nil, fmt.Errorf("parse inventory: %w", err)
	}
	inv.applyDefaults()
	if err := inv.validate(knownDriver); err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	return &inv, nil
}

func (inv *Inventory) applyDefaults() {
	d := &inv.Defaults
	d.Concurrency = orDefault(d.Concurrency, DefaultConcurrency)
	d.Port = orDefault(d.Port, DefaultPort)
	d.Timeout = orDefault(d.Timeout, Duration(DefaultTimeout))
	d.MinSizeRatio = orDefault(d.MinSizeRatio, DefaultMinSizeRatio)
	for name, j := range inv.JumpHosts {
		j.Port = orDefault(j.Port, d.Port)
		j.KnownHosts = orDefault(j.KnownHosts, d.KnownHosts)
		j.SSH = j.SSH.over(d.SSH)
		inv.JumpHosts[name] = j
	}
	for i := range inv.Devices {
		dev := &inv.Devices[i]
		dev.Transport = orDefault(dev.Transport, TransportSSH)
		port := d.Port
		if dev.Transport == TransportTelnet {
			port = DefaultTelnetPort
		}
		dev.Port = orDefault(dev.Port, port)
		dev.Timeout = orDefault(dev.Timeout, d.Timeout)
		dev.KnownHosts = orDefault(dev.KnownHosts, d.KnownHosts)
		if dev.MinSizeRatio == nil {
			dev.MinSizeRatio = &d.MinSizeRatio
		}
		dev.SSH = dev.SSH.over(d.SSH)
	}
}

func (s SSH) over(base SSH) SSH {
	return SSH{
		KeyExchanges:      orDefaultSlice(s.KeyExchanges, base.KeyExchanges),
		Ciphers:           orDefaultSlice(s.Ciphers, base.Ciphers),
		MACs:              orDefaultSlice(s.MACs, base.MACs),
		HostKeyAlgorithms: orDefaultSlice(s.HostKeyAlgorithms, base.HostKeyAlgorithms),
	}
}

func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

func orDefaultSlice(v, def []string) []string {
	if len(v) == 0 {
		return def
	}
	return v
}

func (inv *Inventory) validate(knownDriver func(string) bool) error {
	var errs []error
	if inv.Defaults.Concurrency < 1 {
		errs = append(errs, errors.New("defaults.concurrency must be positive"))
	}
	if r := inv.Defaults.MinSizeRatio; r < 0 || r > 1 {
		errs = append(errs, errors.New("defaults.min_size_ratio must be between 0 and 1"))
	}
	for name, c := range inv.Credentials {
		field := "credentials." + name
		if c.Password.IsZero() && c.PrivateKey.IsZero() {
			errs = append(errs, fmt.Errorf("%s: password or private_key is required", field))
		}
		if !c.PrivateKeyPassphrase.IsZero() && c.PrivateKey.IsZero() {
			errs = append(errs, fmt.Errorf("%s: private_key_passphrase needs private_key", field))
		}
		errs = append(errs,
			c.Username.validate(field+".username", true),
			c.PrivateKeyPassphrase.validate(field+".private_key_passphrase", false),
			c.Password.validate(field+".password", false),
			c.PrivateKey.validate(field+".private_key", false),
			c.EnablePassword.validate(field+".enable_password", false),
		)
	}
	for name, j := range inv.JumpHosts {
		field := "jump_hosts." + name
		if j.Address == "" {
			errs = append(errs, fmt.Errorf("%s.address is required", field))
		}
		if c, ok := inv.Credentials[j.Credential]; !ok {
			errs = append(errs, fmt.Errorf("%s: unknown credential %q", field, j.Credential))
		} else if c.Username.IsZero() {
			errs = append(errs, fmt.Errorf("%s: credential %q has no username", field, j.Credential))
		}
		if j.KnownHosts == "" {
			errs = append(errs, fmt.Errorf("%s: known_hosts is required", field))
		}
	}
	seen := make(map[string]struct{}, len(inv.Devices))
	for i, d := range inv.Devices {
		field := fmt.Sprintf("devices[%d]", i)
		if !nameRe.MatchString(d.Name) {
			errs = append(errs, fmt.Errorf("%s: name %q must match %s", field, d.Name, nameRe))
		}
		if _, dup := seen[d.Name]; dup {
			errs = append(errs, fmt.Errorf("%s: duplicate name %q", field, d.Name))
		}
		seen[d.Name] = struct{}{}
		if d.Address == "" {
			errs = append(errs, fmt.Errorf("%s: address is required", field))
		}
		if !knownDriver(d.Driver) {
			errs = append(errs, fmt.Errorf("%s: unknown driver %q", field, d.Driver))
		}
		cred, ok := inv.Credentials[d.Credential]
		if !ok {
			errs = append(errs, fmt.Errorf("%s: unknown credential %q", field, d.Credential))
		}
		if _, ok := inv.JumpHosts[d.Jump]; d.Jump != "" && !ok {
			errs = append(errs, fmt.Errorf("%s: unknown jump host %q", field, d.Jump))
		}
		switch d.Transport {
		case TransportSSH:
			if d.KnownHosts == "" {
				errs = append(errs, fmt.Errorf("%s: known_hosts is required (host keys are always verified)", field))
			}
			if ok && cred.Username.IsZero() {
				errs = append(errs, fmt.Errorf("%s: credential %q has no username", field, d.Credential))
			}
		case TransportTelnet:
			if d.Jump != "" {
				errs = append(errs, fmt.Errorf("%s: jump hosts are not supported with telnet", field))
			}
			if ok && cred.Password.IsZero() {
				errs = append(errs, fmt.Errorf("%s: telnet needs a password in credential %q", field, d.Credential))
			}
		default:
			errs = append(errs, fmt.Errorf("%s: transport must be %s or %s", field, TransportSSH, TransportTelnet))
		}
		if r := *d.MinSizeRatio; r < 0 || r > 1 {
			errs = append(errs, fmt.Errorf("%s: min_size_ratio must be between 0 and 1", field))
		}
	}
	return errors.Join(errs...)
}
