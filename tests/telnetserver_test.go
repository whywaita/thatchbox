package tests

import (
	"bufio"
	"io"
	"net"
	"sync"
	"testing"
)

// Telnet protocol bytes (RFC 854).
const (
	tnIAC  = 255
	tnDONT = 254
	tnDO   = 253
	tnWONT = 252
	tnWILL = 251
	tnSB   = 250
	tnSE   = 240

	tnOptEcho  = 1
	tnOptSGA   = 3
	tnOptTType = 24
	tnOptNAWS  = 31
)

// telnetServer is an in-process telnet server in front of a fakeDevice. It
// negotiates options, asks for a login like Cisco IOS does, and records the
// option replies the client sends.
type telnetServer struct {
	addr string
	opts telnetServerOptions

	mu      sync.Mutex
	replies [][3]byte
}

type telnetServerOptions struct {
	username string // empty: line password only ("Password:" without "Username:")
	password string
	device   *fakeDevice
}

func startTelnetServer(t *testing.T, o telnetServerOptions) *telnetServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &telnetServer{addr: ln.Addr().String(), opts: o}
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
func (s *telnetServer) Replies() [][3]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][3]byte(nil), s.replies...)
}

func (s *telnetServer) handle(c net.Conn) {
	defer c.Close()
	// Negotiation split across writes, with a subnegotiation in between, to
	// exercise the client's state across reads.
	for _, chunk := range [][]byte{
		{tnIAC, tnWILL, tnOptEcho, tnIAC},
		{tnWILL, tnOptSGA, tnIAC, tnDO, tnOptTType},
		{tnIAC, tnDO, tnOptNAWS, tnIAC, tnSB, tnOptTType, 1, tnIAC, tnSE},
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
	s.opts.device.serve(&pipeConn{Reader: r, Writer: c, closers: []io.Closer{c}})
}

func (s *telnetServer) login(w io.Writer, r *bufio.Reader) bool {
	write := func(str string) bool {
		_, err := io.WriteString(w, str)
		return err == nil
	}
	if !write("\r\n\r\nUser Access Verification\r\n\r\n") {
		return false
	}
	for range 3 {
		user := ""
		if s.opts.username != "" {
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
		if user == s.opts.username && pw == s.opts.password {
			return write("\r\n")
		}
		if !write("\r\n% Login invalid\r\n\r\n") {
			return false
		}
	}
	write("% Bad passwords\r\n")
	return false
}

func (s *telnetServer) record(cmd [3]byte) {
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
		if b != tnIAC {
			p[n] = b
			n++
			continue
		}
		cmd, err := t.r.ReadByte()
		if err != nil {
			return n, err
		}
		if cmd == tnIAC {
			p[n] = tnIAC
			n++
			continue
		}
		opt, err := t.r.ReadByte()
		if err != nil {
			return n, err
		}
		t.record([3]byte{tnIAC, cmd, opt})
	}
	return n, nil
}
