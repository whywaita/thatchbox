// Package shell drives an interactive device CLI over any byte stream
// (an SSH session with a PTY, or telnet) using a driver definition.
package shell

import (
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"

	"github.com/whywaita/thatchbox/internal/driver"
)

// Errors returned by the session. They never contain device output.
var (
	ErrTimeout = errors.New("timed out waiting for the device prompt")
	ErrClosed  = errors.New("connection closed before the device prompt")
	ErrEnable  = errors.New("could not enter privileged mode")
	ErrLogin   = errors.New("login rejected")
)

const (
	newline   = "\n"
	readChunk = 32 * 1024
)

var (
	ansiEscape = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|\x1b[=>]`)
	// pagerErase is what CLIs print to wipe a pager prompt after a key press:
	// "\b\b\b   \b\b\b" (Cisco) or repeated "\b \b" (NEC IX).
	pagerErase = regexp.MustCompile(`(?:\x08+ +)*\x08+`)
	// Login prompts of devices that authenticate inside the stream (telnet).
	usernamePrompt = regexp.MustCompile(`(?i)(?:user ?name|login)\s*:\s*$`)
	passwordPrompt = regexp.MustCompile(`(?i)password\s*:\s*$`)
)

// Login is answered when the device asks for it in the stream (telnet).
// An empty Username is for a line password without a username prompt.
type Login struct {
	Username string
	Password string
}

// Session is one interactive CLI.
type Session struct {
	conn   io.ReadWriteCloser
	drv    *driver.Driver
	prompt string // literal prompt learned after login, trimmed
	chunks chan []byte
	done   chan struct{} // closed when the read loop ends
	closed chan struct{} // closed by Close
	once   sync.Once
	buf    strings.Builder
}

// Open waits for the first prompt, enters privileged mode when the driver
// asks for it, and runs the driver's setup commands.
func Open(ctx context.Context, conn io.ReadWriteCloser, drv *driver.Driver, enablePassword string) (*Session, error) {
	return open(ctx, conn, drv, nil, enablePassword)
}

// OpenLogin is Open for a stream that asks for a username and password
// before the first prompt.
func OpenLogin(ctx context.Context, conn io.ReadWriteCloser, drv *driver.Driver, login Login, enablePassword string) (*Session, error) {
	return open(ctx, conn, drv, &login, enablePassword)
}

func open(ctx context.Context, conn io.ReadWriteCloser, drv *driver.Driver, login *Login, enablePassword string) (*Session, error) {
	s := &Session{conn: conn, drv: drv, chunks: make(chan []byte, 1), done: make(chan struct{}), closed: make(chan struct{})}
	go s.readLoop()
	start := s.learnPrompt
	if login != nil {
		start = func(ctx context.Context) error { return s.login(ctx, *login) }
	}
	if err := start(ctx); err != nil {
		s.Close()
		return nil, err
	}
	if err := s.enable(ctx, enablePassword); err != nil {
		s.Close()
		return nil, err
	}
	for _, cmd := range drv.Setup {
		// Setup failures (e.g. an unsupported pager command) are tolerated;
		// the pager definition still handles paging.
		if _, err := s.Run(ctx, cmd); err != nil {
			s.Close()
			return nil, err
		}
	}
	return s, nil
}

// Close closes the underlying connection.
func (s *Session) Close() error {
	s.once.Do(func() { close(s.closed) })
	return s.conn.Close()
}

// Run sends cmd and returns its output without the echoed command and the
// trailing prompt.
func (s *Session) Run(ctx context.Context, cmd string) (string, error) {
	if err := s.send(cmd + newline); err != nil {
		return "", ErrClosed
	}
	out, err := s.expect(ctx, func(tail string) bool { return strings.TrimSpace(tail) == s.prompt })
	if err != nil {
		return "", err
	}
	return stripEcho(out, cmd), nil
}

func (s *Session) learnPrompt(ctx context.Context) error {
	_, err := s.expect(ctx, s.matchPrompt)
	return err
}

// login answers username and password prompts until the device prompt
// appears. A prompt asked again after the password means rejection.
func (s *Session) login(ctx context.Context, l Login) error {
	const (
		askedNothing = iota
		askedUsername
		askedPassword
	)
	sentUsername, sentPassword := false, false
	for {
		asked := askedNothing
		_, err := s.expect(ctx, func(tail string) bool {
			switch {
			case usernamePrompt.MatchString(tail):
				asked = askedUsername
				return true
			case passwordPrompt.MatchString(tail):
				asked = askedPassword
				return true
			}
			return s.matchPrompt(tail)
		})
		switch {
		case err != nil && sentPassword && errors.Is(err, ErrClosed):
			// Devices hang up after too many failures.
			return ErrLogin
		case err != nil:
			return err
		}
		switch asked {
		case askedNothing:
			return nil
		case askedUsername:
			if sentUsername || sentPassword || l.Username == "" {
				return ErrLogin
			}
			sentUsername = true
			err = s.send(l.Username + newline)
		case askedPassword:
			if sentPassword || l.Password == "" {
				return ErrLogin
			}
			sentPassword = true
			err = s.send(l.Password + newline)
		}
		if err != nil {
			return ErrClosed
		}
	}
}

func (s *Session) matchPrompt(tail string) bool {
	if !s.drv.Prompt.MatchString(tail) {
		return false
	}
	s.prompt = strings.TrimSpace(tail)
	return true
}

func (s *Session) enable(ctx context.Context, password string) error {
	e := s.drv.Enable
	if e == nil || !e.When.MatchString(s.prompt) {
		return nil
	}
	if err := s.send(e.Command + newline); err != nil {
		return ErrClosed
	}
	askedPassword := false
	if _, err := s.expect(ctx, func(tail string) bool {
		if e.PasswordPrompt.MatchString(tail) {
			askedPassword = true
			return true
		}
		return s.matchPrompt(tail)
	}); err != nil {
		return err
	}
	if askedPassword {
		if password == "" {
			return ErrEnable
		}
		if err := s.send(password + newline); err != nil {
			return ErrClosed
		}
		if err := s.learnPrompt(ctx); err != nil {
			return err
		}
	}
	if e.When.MatchString(s.prompt) {
		return ErrEnable
	}
	return nil
}

func (s *Session) send(data string) error {
	_, err := io.WriteString(s.conn, data)
	return err
}

func (s *Session) readLoop() {
	defer close(s.done)
	for {
		b := make([]byte, readChunk)
		n, err := s.conn.Read(b)
		if n > 0 {
			select {
			case s.chunks <- b[:n]:
			case <-s.closed:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// expect reads until done reports true for the current last line. It
// answers pager prompts on the way and returns everything read before the
// last line.
func (s *Session) expect(ctx context.Context, done func(tail string) bool) (string, error) {
	s.buf.Reset()
	for {
		select {
		case <-ctx.Done():
			return "", ErrTimeout
		case <-s.done:
			// Drain what arrived before the close.
			select {
			case b := <-s.chunks:
				if out, ok, err := s.consume(b, done); ok || err != nil {
					return out, err
				}
			default:
			}
			return "", ErrClosed
		case b := <-s.chunks:
			if out, ok, err := s.consume(b, done); ok || err != nil {
				return out, err
			}
		}
	}
}

func (s *Session) consume(b []byte, done func(string) bool) (string, bool, error) {
	s.buf.Write(b)
	text := s.buf.String()
	if p := s.drv.Pager; p != nil {
		if loc := p.Pattern.FindStringIndex(lastLine(text)); loc != nil {
			text = text[:len(text)-len(lastLine(text))+loc[0]]
			s.buf.Reset()
			s.buf.WriteString(text)
			if err := s.send(p.Send); err != nil {
				return "", false, ErrClosed
			}
			return "", false, nil
		}
	}
	clean := clean(text)
	tail := lastLine(clean)
	if !done(tail) {
		return "", false, nil
	}
	return clean[:len(clean)-len(tail)], true, nil
}

func clean(s string) string {
	s = ansiEscape.ReplaceAllString(s, "")
	s = pagerErase.ReplaceAllString(s, "")
	return strings.ReplaceAll(s, "\r", "")
}

func lastLine(s string) string {
	return s[strings.LastIndexByte(s, '\n')+1:]
}

func stripEcho(out, cmd string) string {
	first, rest, found := strings.Cut(out, "\n")
	if found && strings.Contains(first, strings.TrimSpace(cmd)) {
		return rest
	}
	return out
}
