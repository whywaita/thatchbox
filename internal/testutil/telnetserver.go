package testutil

import (
	"bufio"
	"io"
	"net"
	"sync"
	"testing"
)

// Telnet protocol bytes (RFC 854).
const (
	IAC  = 255
	DONT = 254
	DO   = 253
	WONT = 252
	WILL = 251
	SB   = 250
	SE   = 240

	OptEcho  = 1
	OptSGA   = 3
	OptTType = 24
	OptNAWS  = 31
)

// TelnetServer is an in-process telnet server in front of a FakeDevice. It
// negotiates options, asks for a login like Cisco IOS does, and records the
// option replies the client sends.
type TelnetServer struct {
	Addr string
	opts TelnetServerOptions

	mu      sync.Mutex
	replies [][3]byte
}

type TelnetServerOptions struct {
	Username string // empty: line password only ("Password:" without "Username:")
	Password string
	Device   *FakeDevice
}

func StartTelnetServer(t *testing.T, o TelnetServerOptions) *TelnetServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &TelnetServer{Addr: ln.Addr().String(), opts: o}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	return s
}

// Replies returns the option negotiation commands received from the client.
func (s *TelnetServer) Replies() [][3]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][3]byte(nil), s.replies...)
}

func (s *TelnetServer) handle(c net.Conn) {
	defer c.Close()
	// Negotiation split across writes, with a subnegotiation in between, to
	// exercise the client's state across reads.
	for _, chunk := range [][]byte{
		{IAC, WILL, OptEcho, IAC},
		{WILL, OptSGA, IAC, DO, OptTType},
		{IAC, DO, OptNAWS, IAC, SB, OptTType, 1, IAC, SE},
	} {
		if _, err := c.Write(chunk); err != nil {
			return
		}
	}
	r := bufio.NewReader(&telnetInput{r: bufio.NewReader(c), record: s.record})
	if !s.login(c, r) {
		return
	}
	// The device reads the rest of the stream, including bytes r buffered.
	s.opts.Device.serve(&pipeConn{Reader: r, Writer: c, closers: []io.Closer{c}})
}

func (s *TelnetServer) login(w io.Writer, r *bufio.Reader) bool {
	write := func(str string) bool {
		_, err := io.WriteString(w, str)
		return err == nil
	}
	if !write("\r\n\r\nUser Access Verification\r\n\r\n") {
		return false
	}
	for range 3 {
		user := ""
		if s.opts.Username != "" {
			if !write("Username: ") {
				return false
			}
			var err error
			if user, err = readLine(r); err != nil {
				return false
			}
			// The server echoes the username, as IOS does.
			if !write(user + "\r\n") {
				return false
			}
		}
		if !write("Password: ") {
			return false
		}
		pw, err := readLine(r)
		if err != nil {
			return false
		}
		if user == s.opts.Username && pw == s.opts.Password {
			return write("\r\n")
		}
		if !write("\r\n% Login invalid\r\n\r\n") {
			return false
		}
	}
	write("% Bad passwords\r\n")
	return false
}

func (s *TelnetServer) record(cmd [3]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replies = append(s.replies, cmd)
}

// telnetInput removes option commands from the client's stream.
type telnetInput struct {
	r      *bufio.Reader
	record func([3]byte)
}

func (t *telnetInput) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if n > 0 && t.r.Buffered() == 0 {
			break
		}
		b, err := t.r.ReadByte()
		if err != nil {
			return n, err
		}
		if b != IAC {
			p[n] = b
			n++
			continue
		}
		cmd, err := t.r.ReadByte()
		if err != nil {
			return n, err
		}
		if cmd == IAC {
			p[n] = IAC
			n++
			continue
		}
		opt, err := t.r.ReadByte()
		if err != nil {
			return n, err
		}
		t.record([3]byte{IAC, cmd, opt})
	}
	return n, nil
}
