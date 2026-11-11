package tests

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"
)

// sshServer is an in-process SSH server that exposes a fakeDevice as its
// shell and optionally forwards direct-tcpip channels (jump host).
type sshServer struct {
	addr    string
	hostKey ssh.PublicKey
	device  *fakeDevice
	opts    sshServerOptions

	mu       sync.Mutex
	forwards int
}

type sshServerOptions struct {
	user, password string
	authorizedKey  ssh.PublicKey // accept public key authentication with this key
	requireBoth    bool          // require the key and then the password
	device         *fakeDevice
	ciphers        []string // restrict server ciphers
	allowForward   bool
	rejectPTY      bool // refuse pty-req, as a device without a shell would
	// rejectKeyboardInteractive offers keyboard-interactive and rejects it
	// without sending any question, as some Cisco IOS versions do.
	rejectKeyboardInteractive bool
}

func startSSHServer(t *testing.T, o sshServerOptions) *sshServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	passwordCallback := func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if o.password != "" && c.User() == o.user && string(pw) == o.password {
			return nil, nil
		}
		return nil, errAuthFailed
	}
	cfg := &ssh.ServerConfig{}
	if !o.requireBoth {
		cfg.PasswordCallback = passwordCallback
	}
	if o.authorizedKey != nil {
		cfg.PublicKeyCallback = func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() != o.user || !bytes.Equal(key.Marshal(), o.authorizedKey.Marshal()) {
				return nil, errAuthFailed
			}
			if o.requireBoth {
				return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{PasswordCallback: passwordCallback}}
			}
			return nil, nil
		}
	}
	if o.rejectKeyboardInteractive {
		cfg.KeyboardInteractiveCallback = func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			return nil, errAuthFailed
		}
	}
	cfg.Ciphers = o.ciphers
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &sshServer{addr: ln.Addr().String(), hostKey: signer.PublicKey(), device: o.device, opts: o}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c, cfg, o.allowForward)
		}
	}()
	return s
}

type authError string

func (e authError) Error() string { return string(e) }

const errAuthFailed = authError("denied")

func (s *sshServer) handle(c net.Conn, cfg *ssh.ServerConfig, allowForward bool) {
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			ch, chReqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go s.session(ch, chReqs)
		case "direct-tcpip":
			if !allowForward {
				_ = nc.Reject(ssh.Prohibited, "no forwarding")
				continue
			}
			go s.forward(nc)
		default:
			_ = nc.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}

func (s *sshServer) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for r := range reqs {
		switch r.Type {
		case "pty-req":
			_ = r.Reply(!s.opts.rejectPTY, nil)
		case "shell":
			_ = r.Reply(true, nil)
			go s.device.serve(ch)
		default:
			_ = r.Reply(false, nil)
		}
	}
}

func (s *sshServer) forward(nc ssh.NewChannel) {
	extra := nc.ExtraData()
	hostLen := binary.BigEndian.Uint32(extra[:4])
	host := string(extra[4 : 4+hostLen])
	port := binary.BigEndian.Uint32(extra[4+hostLen : 8+hostLen])
	target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, "dial failed")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		target.Close()
		return
	}
	s.mu.Lock()
	s.forwards++
	s.mu.Unlock()
	go ssh.DiscardRequests(reqs)
	go func() {
		_, _ = io.Copy(ch, target)
		ch.Close()
	}()
	_, _ = io.Copy(target, ch)
	target.Close()
}

func (s *sshServer) Forwards() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.forwards
}

// writeKnownHosts writes a known_hosts file trusting the given servers.
func writeKnownHosts(t *testing.T, servers ...*sshServer) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "known_hosts")
	var b []byte
	for _, s := range servers {
		b = append(b, knownhosts.Line([]string{knownhosts.Normalize(s.addr)}, s.hostKey)+"\n"...)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func hostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return h, port
}
