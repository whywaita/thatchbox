// Package telnet is a minimal telnet client (RFC 854) for devices that offer
// no SSH. It refuses every option except server echo and suppress-go-ahead,
// so the stream behaves like a plain terminal. Telnet is cleartext: use it
// only on networks where that is acceptable.
package telnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
)

// ErrConnect means the TCP connection could not be opened.
var ErrConnect = errors.New("tcp connection failed")

// Protocol bytes.
const (
	iac  = 255
	dont = 254
	do   = 253
	wont = 252
	will = 251
	sb   = 250
	se   = 240

	optEcho = 1
	optSGA  = 3

	cr  = '\r'
	lf  = '\n'
	nul = 0
)

// decoder states
const (
	stData = iota
	stCR
	stIAC
	stOption
	stSub
	stSubIAC
)

// Dial opens a telnet connection. Cancelling ctx before Dial returns aborts it.
func Dial(ctx context.Context, host string, port int) (*Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() != nil {
			// The device timeout expired; report it as such, not as unreachable.
			return nil, fmt.Errorf("connect %s: %w", addr, ctx.Err())
		}
		return nil, fmt.Errorf("%w: %s", ErrConnect, addr)
	}
	return NewConn(c), nil
}

// Conn removes telnet commands from what it reads, answers option requests,
// and encodes what it writes.
type Conn struct {
	conn io.ReadWriteCloser

	wmu sync.Mutex

	// Used by Read only.
	raw      []byte
	state    int
	command  byte
	answered map[[2]byte]bool
}

// NewConn wraps an established connection.
func NewConn(c io.ReadWriteCloser) *Conn {
	return &Conn{conn: c, answered: make(map[[2]byte]bool)}
}

// Read returns data bytes only. It blocks until at least one is available.
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.raw) < len(p) {
		c.raw = make([]byte, len(p))
	}
	for {
		m, err := c.conn.Read(c.raw[:len(p)])
		n := c.decode(c.raw[:m], p)
		if n > 0 || err != nil {
			return n, err
		}
	}
}

// decode copies the data bytes of in to out (len(out) >= len(in)).
func (c *Conn) decode(in, out []byte) int {
	n := 0
	for _, b := range in {
		if c.state == stCR {
			c.state = stData
			if b == nul {
				continue
			}
		}
		switch c.state {
		case stData:
			switch b {
			case iac:
				c.state = stIAC
				continue
			case cr:
				c.state = stCR
			}
			out[n] = b
			n++
		case stIAC:
			c.state = stData
			switch b {
			case iac:
				out[n] = iac
				n++
			case do, dont, will, wont:
				c.command, c.state = b, stOption
			case sb:
				c.state = stSub
			}
		case stOption:
			c.state = stData
			c.negotiate(c.command, b)
		case stSub:
			if b == iac {
				c.state = stSubIAC
			}
		case stSubIAC:
			c.state = stSub
			if b == se {
				c.state = stData
			}
		}
	}
	return n
}

// negotiate answers each request once; nothing is enabled on the client
// side, so DONT and WONT need no reply.
func (c *Conn) negotiate(command, option byte) {
	var reply byte
	switch command {
	case do:
		reply = wont
	case will:
		reply = dont
		if option == optEcho || option == optSGA {
			reply = do
		}
	default:
		return
	}
	key := [2]byte{command, option}
	if c.answered[key] {
		return
	}
	c.answered[key] = true
	c.wmu.Lock()
	defer c.wmu.Unlock()
	// A write error surfaces on the next Read or Write.
	_, _ = c.conn.Write([]byte{iac, reply, option})
}

// Write escapes IAC and sends a newline as CR LF.
func (c *Conn) Write(p []byte) (int, error) {
	out := make([]byte, 0, len(p)+len(p)/8+2)
	for i, b := range p {
		switch {
		case b == iac:
			out = append(out, iac, iac)
		case b == lf && (i == 0 || p[i-1] != cr):
			out = append(out, cr, lf)
		default:
			out = append(out, b)
		}
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.conn.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the connection.
func (c *Conn) Close() error { return c.conn.Close() }
