package telnet_test

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/whywaita/thatchbox/internal/telnet"
	"github.com/whywaita/thatchbox/internal/testutil"
)

func TestTelnetNegotiationEdgeCases(t *testing.T) {
	client, server := net.Pipe()
	conn := telnet.NewConn(client)
	defer conn.Close()
	defer server.Close()

	go func() {
		_, _ = server.Write([]byte{
			testutil.IAC, testutil.DO, testutil.OptNAWS,
			testutil.IAC, testutil.DO, testutil.OptNAWS, // repeated: no second reply
			testutil.IAC, testutil.DONT, testutil.OptEcho, testutil.IAC, testutil.WONT, testutil.OptSGA, // no replies
			testutil.IAC, testutil.SB, testutil.OptTType, testutil.IAC, testutil.IAC, 'x', testutil.IAC, testutil.SE,
			testutil.IAC, 241, // NOP is ignored
			'o', 'k',
		})
	}()
	replies := make(chan []byte, 1)
	go func() {
		b := make([]byte, 3)
		_, _ = io.ReadFull(server, b)
		replies <- b
	}()
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "ok" {
		t.Fatalf("data = %q", got)
	}
	if got := <-replies; !bytes.Equal(got, []byte{testutil.IAC, testutil.WONT, testutil.OptNAWS}) {
		t.Fatalf("reply = %v", got)
	}
	if n, err := conn.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read = %d %v", n, err)
	}
}

func TestTelnetReadReturnsEOF(t *testing.T) {
	client, server := net.Pipe()
	conn := telnet.NewConn(client)
	defer conn.Close()
	go func() {
		_, _ = server.Write([]byte{testutil.IAC, testutil.WILL, testutil.OptEcho})
		server.Close()
	}()
	go func() { _, _ = io.Copy(io.Discard, server) }()
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
}

func TestTelnetWriteAfterClose(t *testing.T) {
	client, server := net.Pipe()
	server.Close()
	conn := telnet.NewConn(client)
	if _, err := conn.Write([]byte("x\n")); err == nil {
		t.Fatal("write to closed connection succeeded")
	}
}
