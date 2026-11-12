// Package sshdial opens an interactive SSH shell on a device, optionally
// through a jump host, always verifying host keys against known_hosts.
package sshdial

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"

	"github.com/whywaita/thatchbox/internal/inventory"
)

// Error categories. Wrapped errors never contain terminal output.
var (
	ErrConnect   = errors.New("tcp connection failed")
	ErrHostKey   = errors.New("host key verification failed")
	ErrAuth      = errors.New("authentication failed")
	ErrHandshake = errors.New("ssh handshake failed")
	ErrSession   = errors.New("could not start shell")
)

const (
	appendPrefix = "+"
	ptyTerm      = "vt100"
	ptyCols      = 511
	ptyRows      = 24
	ptySpeed     = 115200
)

// Target is one SSH endpoint with resolved credentials.
type Target struct {
	Host       string
	Port       int
	Username   string
	Password   string
	PrivateKey []byte
	// PrivateKeyPassphrase decrypts PrivateKey when it is encrypted.
	PrivateKeyPassphrase string
	KnownHosts           string
	Algorithms           inventory.SSH
}

func (t Target) addr() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

// Open connects to t (through jump when not nil) and starts a shell with a
// PTY. Closing the returned stream closes every underlying connection.
// Cancelling ctx before Open returns aborts the connection.
func Open(ctx context.Context, t Target, jump *Target) (io.ReadWriteCloser, error) {
	var closers []io.Closer
	closeAll := func() {
		for _, c := range slices.Backward(closers) {
			_ = c.Close()
		}
	}
	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	if jump != nil {
		jc, err := connect(ctx, *jump, dial)
		if err != nil {
			return nil, fmt.Errorf("jump host: %w", err)
		}
		closers = append(closers, jc)
		dial = func(ctx context.Context, addr string) (net.Conn, error) {
			return jc.DialContext(ctx, "tcp", addr)
		}
	}
	client, err := connect(ctx, t, dial)
	if err != nil {
		closeAll()
		return nil, err
	}
	closers = append(closers, client)
	stream, err := startShell(client)
	if err != nil {
		closeAll()
		return nil, err
	}
	closers = append(closers, stream)
	return &closeStream{ReadWriter: stream, close: sync.OnceFunc(closeAll)}, nil
}

type closeStream struct {
	io.ReadWriter
	close func()
}

func (c *closeStream) Close() error {
	c.close()
	return nil
}

func connect(ctx context.Context, t Target, dial func(context.Context, string) (net.Conn, error)) (*ssh.Client, error) {
	cfg, err := clientConfig(t)
	if err != nil {
		return nil, err
	}
	addr := t.addr()
	conn, err := dial(ctx, addr)
	if err != nil {
		if ctx.Err() != nil {
			// The device timeout expired; report it as such, not as unreachable.
			return nil, fmt.Errorf("connect %s: %w", addr, ctx.Err())
		}
		return nil, fmt.Errorf("%w: %s", ErrConnect, addr)
	}
	// Abort the handshake when ctx ends.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, classify(ctx, addr, err)
	}
	return ssh.NewClient(sc, chans, reqs), nil
}

func classify(ctx context.Context, addr string, err error) error {
	switch {
	case knownhosts.IsHostKeyChanged(err) || knownhosts.IsHostUnknown(err):
		return fmt.Errorf("%w: %s", ErrHostKey, addr)
	case ctx.Err() != nil:
		return fmt.Errorf("%w: %s: %w", ErrHandshake, addr, ctx.Err())
	case strings.Contains(err.Error(), "unable to authenticate"),
		// x/crypto reports a keyboard-interactive rejection without any
		// question (SSH_MSG_USERAUTH_FAILURE = 51) as a protocol error.
		strings.Contains(err.Error(), "unexpected message type 51"):
		return fmt.Errorf("%w: %s", ErrAuth, addr)
	default:
		// x/crypto handshake errors describe negotiation, not device output.
		return fmt.Errorf("%w: %s: %w", ErrHandshake, addr, err)
	}
}

func clientConfig(t Target) (*ssh.ClientConfig, error) {
	if t.KnownHosts == "" {
		return nil, errors.New("known_hosts is required")
	}
	db, err := knownhosts.NewDB(t.KnownHosts)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}
	auth, err := authMethods(t)
	if err != nil {
		return nil, err
	}
	supported, insecure := ssh.SupportedAlgorithms(), ssh.InsecureAlgorithms()
	cfg := &ssh.ClientConfig{
		User:            t.Username,
		Auth:            auth,
		HostKeyCallback: db.HostKeyCallback(),
	}
	var errs []error
	pick := func(kind string, want, defaults []string, known ...[]string) []string {
		out, err := resolve(want, defaults, slices.Concat(known...))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", kind, err))
		}
		return out
	}
	// x/crypto exposes no default-preference lists; SupportedAlgorithms is
	// its secure set, which is what an empty config negotiates from.
	cfg.KeyExchanges = pick("kex", t.Algorithms.KeyExchanges, supported.KeyExchanges, supported.KeyExchanges, insecure.KeyExchanges)
	cfg.Ciphers = pick("ciphers", t.Algorithms.Ciphers, supported.Ciphers, supported.Ciphers, insecure.Ciphers)
	cfg.MACs = pick("macs", t.Algorithms.MACs, supported.MACs, supported.MACs, insecure.MACs)
	hostKeyDefaults := db.HostKeyAlgorithms(t.addr())
	if len(hostKeyDefaults) == 0 {
		hostKeyDefaults = supported.HostKeys
	}
	cfg.HostKeyAlgorithms = pick("host_key_algorithms", t.Algorithms.HostKeyAlgorithms, hostKeyDefaults, supported.HostKeys, insecure.HostKeys)
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return cfg, nil
}

// resolve applies an override list: entries prefixed with "+" extend
// defaults, plain entries replace them. Every name must be known.
func resolve(want, defaults, known []string) ([]string, error) {
	if len(want) == 0 {
		return defaults, nil
	}
	appendOnly := strings.HasPrefix(want[0], appendPrefix)
	out := make([]string, 0, len(defaults)+len(want))
	if appendOnly {
		out = append(out, defaults...)
	}
	for _, w := range want {
		if strings.HasPrefix(w, appendPrefix) != appendOnly {
			return nil, errors.New("do not mix \"+name\" and plain names")
		}
		name := strings.TrimPrefix(w, appendPrefix)
		if !slices.Contains(known, name) {
			return nil, fmt.Errorf("unsupported algorithm %q", name)
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out, nil
}

func authMethods(t Target) ([]ssh.AuthMethod, error) {
	// Order matters: the key is offered first, then the password. A server
	// that requires both (partial success) gets them in that order.
	methods := make([]ssh.AuthMethod, 0, 3)
	if len(t.PrivateKey) > 0 {
		signer, err := parseKey(t.PrivateKey, t.PrivateKeyPassphrase)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if t.Password != "" {
		pw := t.Password
		methods = append(methods,
			ssh.Password(pw),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = pw
				}
				return answers, nil
			}),
		)
	}
	if len(methods) == 0 {
		return nil, errors.New("no password or private key")
	}
	return methods, nil
}

// parseKey never wraps parser errors: they may quote key material.
func parseKey(key []byte, passphrase string) (ssh.Signer, error) {
	if passphrase != "" {
		signer, err := ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
		if err != nil {
			return nil, errors.New("private key could not be decrypted with the passphrase")
		}
		return signer, nil
	}
	signer, err := ssh.ParsePrivateKey(key)
	var missing *ssh.PassphraseMissingError
	switch {
	case errors.As(err, &missing):
		return nil, errors.New("private key is encrypted: set private_key_passphrase")
	case err != nil:
		return nil, errors.New("private key could not be parsed")
	}
	return signer, nil
}

type sessionStream struct {
	io.Reader
	io.Writer
	session *ssh.Session
}

func (s *sessionStream) Close() error { return s.session.Close() }

func startShell(c *ssh.Client) (*sessionStream, error) {
	sess, err := c.NewSession()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSession, err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("%w: %w", ErrSession, err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("%w: %w", ErrSession, err)
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: ptySpeed, ssh.TTY_OP_OSPEED: ptySpeed}
	if err := sess.RequestPty(ptyTerm, ptyRows, ptyCols, modes); err != nil {
		sess.Close()
		return nil, fmt.Errorf("%w: pty: %w", ErrSession, err)
	}
	if err := sess.Shell(); err != nil {
		sess.Close()
		return nil, fmt.Errorf("%w: %w", ErrSession, err)
	}
	return &sessionStream{Reader: stdout, Writer: stdin, session: sess}, nil
}
