package tests

import (
	"bufio"
	"io"
	"strings"
	"sync"
)

// fakeDevice imitates a CLI behind a PTY: it echoes input, prints a prompt,
// optionally requires enable, and can page or stall its output.
type fakeDevice struct {
	hostname       string
	banner         string
	enablePassword string // non-empty: start unprivileged ("host>")
	enableCommand  string // non-empty: start unprivileged; this command enters privileged mode (default "enable")
	privCommands   bool   // commands are rejected until privileged mode
	privSuffix     string // default "#"
	userSuffix     string // default ">"
	commands       map[string]string
	pageEvery      int    // >0: insert a pager prompt every N lines until "terminal length 0"
	pagerErase     string // what erases the pager prompt (default: Cisco style)
	stallOn        string // command after which the device never prints a prompt again
	dropOn         string // command after which the device closes mid-output

	mu       sync.Mutex
	received []string
}

const fakePager = " --More-- "

func (f *fakeDevice) prompt(priv bool) string {
	if priv {
		return f.hostname + cmp(f.privSuffix, "#")
	}
	return f.hostname + cmp(f.userSuffix, ">")
}

func cmp(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// Received returns the commands the device saw.
func (f *fakeDevice) Received() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.received...)
}

func (f *fakeDevice) serve(rw io.ReadWriteCloser) {
	defer rw.Close()
	r := bufio.NewReader(rw)
	w := func(s string) bool {
		_, err := io.WriteString(rw, s)
		return err == nil
	}
	priv := f.enablePassword == "" && f.enableCommand == ""
	paging := f.pageEvery > 0
	if !w(f.banner + "\r\n" + f.prompt(priv)) {
		return
	}
	for {
		line, err := readLine(r)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.received = append(f.received, line)
		f.mu.Unlock()
		if !w(line + "\r\n") {
			return
		}
		switch {
		case line == cmp(f.enableCommand, "enable") && !priv && f.enablePassword == "":
			priv = true
		case line == cmp(f.enableCommand, "enable") && !priv:
			if !w("Password: ") {
				return
			}
			pw, err := readLine(r)
			if err != nil {
				return
			}
			if pw == f.enablePassword {
				priv = true
			} else if !w("\r\n% Access denied\r\n") {
				return
			}
		case line == "terminal length 0":
			paging = false
		case line == "exit":
			return
		case line == f.dropOn:
			out := f.commands[line]
			w(strings.ReplaceAll(out[:len(out)/2], "\n", "\r\n"))
			return
		default:
			out, ok := f.commands[line]
			if !ok || (f.privCommands && !priv) {
				if !w("% Invalid input detected at '^' marker.\r\n") {
					return
				}
				break
			}
			if !f.writePaged(rw, r, out, paging) {
				return
			}
			if line == f.stallOn {
				_, _ = io.Copy(io.Discard, r)
				return
			}
		}
		if line != "" && !w("\r\n") {
			return
		}
		if !w(f.prompt(priv)) {
			return
		}
	}
}

func (f *fakeDevice) writePaged(w io.Writer, r *bufio.Reader, out string, paging bool) bool {
	lines := strings.SplitAfter(out, "\n")
	for i, l := range lines {
		if paging && i > 0 && i%f.pageEvery == 0 {
			if _, err := io.WriteString(w, fakePager); err != nil {
				return false
			}
			if _, err := r.ReadByte(); err != nil {
				return false
			}
			if _, err := io.WriteString(w, cmp(f.pagerErase, "\b\b\b\b\b\b\b\b\b\b          \b\b\b\b\b\b\b\b\b\b")); err != nil {
				return false
			}
		}
		if _, err := io.WriteString(w, strings.ReplaceAll(l, "\n", "\r\n")); err != nil {
			return false
		}
	}
	return true
}

func readLine(r *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		switch c {
		case '\n':
			return b.String(), nil
		case '\r':
			if next, err := r.Peek(1); err == nil && next[0] == '\n' {
				_, _ = r.ReadByte()
			}
			return b.String(), nil
		default:
			b.WriteByte(c)
		}
	}
}

// pipeConn joins two io.Pipes into a full-duplex connection.
type pipeConn struct {
	io.Reader
	io.Writer
	closers []io.Closer
}

func (p *pipeConn) Close() error {
	for _, c := range p.closers {
		_ = c.Close()
	}
	return nil
}

// connect starts the device and returns the client side.
func (f *fakeDevice) connect() io.ReadWriteCloser {
	cr, dw := io.Pipe()
	dr, cw := io.Pipe()
	device := &pipeConn{Reader: dr, Writer: dw, closers: []io.Closer{dr, dw}}
	go f.serve(device)
	return &pipeConn{Reader: cr, Writer: cw, closers: []io.Closer{cr, cw}}
}
