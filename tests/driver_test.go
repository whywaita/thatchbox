package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whywaita/thatchbox/internal/driver"
)

func TestBuiltinDriversLoad(t *testing.T) {
	reg, err := driver.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, name := range []string{"cisco_ios", "junos", "nec_ix"} {
		d, ok := reg.Get(name)
		if !ok {
			t.Fatalf("builtin driver %q missing", name)
		}
		if len(d.Outputs) == 0 {
			t.Fatalf("driver %q has no outputs", name)
		}
	}
}

func TestDriverDirectoryOverridesBuiltin(t *testing.T) {
	dir := t.TempDir()
	def := `
name: cisco_ios
prompt: '^\S+#\s*$'
outputs:
  - path: custom
    command: show custom
`
	if err := os.WriteFile(filepath.Join(dir, "cisco_ios.yaml"), []byte(def), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := driver.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	d, _ := reg.Get("cisco_ios")
	if len(d.Outputs) != 1 || d.Outputs[0].Path != "custom" {
		t.Fatalf("override not applied: %+v", d.Outputs)
	}
}

func TestDriverRejectsInvalidDefinitions(t *testing.T) {
	cases := map[string]string{
		"mask without secret group": `
name: bad
prompt: '#$'
outputs: [{path: a, command: show}]
mask: ['password \S+']
`,
		"path traversal": `
name: bad
prompt: '#$'
outputs: [{path: ../evil, command: show}]
`,
		"absolute path": `
name: bad
prompt: '#$'
outputs: [{path: /etc/passwd, command: show}]
`,
		"bad regexp": `
name: bad
prompt: '('
outputs: [{path: a, command: show}]
`,
		"no outputs": `
name: bad
prompt: '#$'
`,
		"duplicate paths": `
name: bad
prompt: '#$'
outputs: [{path: a, command: x}, {path: a, command: y}]
`,
	}
	for name, def := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(def), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := driver.Load(dir); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func mustRegistry(t *testing.T) *driver.Registry {
	t.Helper()
	reg, err := driver.Load("")
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func mustParse(t *testing.T, def string) *driver.Driver {
	t.Helper()
	d, err := driver.Parse([]byte(def))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func ciscoDriver(t *testing.T) *driver.Driver {
	t.Helper()
	d, _ := mustRegistry(t).Get("cisco_ios")
	return d
}

const ciscoRunning = `Building configuration...

Current configuration : 1234 bytes
!
! Last configuration change at 12:00:00 JST Mon Nov 9 2026 by admin
! NVRAM config last updated at 12:00:01 JST Mon Nov 9 2026 by admin
!
version 15.2
hostname example-sw
!
enable secret 9 $9$abcdefghijklmnop$qrstuvwxyz0123456789
username admin privilege 15 secret 9 $9$zzzzzzzzzzzz$yyyyyyyyyyyy
!
ntp clock-period 36028797
snmp-server community s3cr3t-comm RO
crypto isakmp key psk-value address 0.0.0.0
line vty 0 4
 password 7 0822455D0A16
!
end
`

func TestCiscoProcessNormalizesAndMasks(t *testing.T) {
	d := ciscoDriver(t)
	out, err := d.Process(d.Outputs[0], ciscoRunning)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	for _, leaked := range []string{
		"$9$abcdefghijklmnop", "$9$zzzzzzzzzzzz", "s3cr3t-comm", "psk-value", "0822455D0A16",
		"Last configuration change", "NVRAM config last updated", "ntp clock-period",
		"Building configuration", "Current configuration :",
	} {
		if strings.Contains(out, leaked) {
			t.Errorf("output still contains %q:\n%s", leaked, out)
		}
	}
	for _, kept := range []string{"hostname example-sw", "enable secret 9 <masked>", "snmp-server community <masked> RO", "\nend\n"} {
		if !strings.Contains(out, kept) {
			t.Errorf("output lacks %q:\n%s", kept, out)
		}
	}
}

func TestProcessIsStableAcrossVolatileChanges(t *testing.T) {
	d := ciscoDriver(t)
	a, err := d.Process(d.Outputs[0], ciscoRunning)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.NewReplacer("12:00:00", "13:14:15", "36028797", "36028800", "1234 bytes", "1240 bytes").Replace(ciscoRunning)
	b, err := d.Process(d.Outputs[0], changed)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("volatile lines leaked into output:\n%s\n---\n%s", a, b)
	}
}

func TestProcessRejectsMissingEndMarker(t *testing.T) {
	d := ciscoDriver(t)
	truncated := ciscoRunning[:strings.Index(ciscoRunning, "line vty")]
	if _, err := d.Process(d.Outputs[0], truncated); err == nil {
		t.Fatal("expected incomplete output error")
	}
}

func TestProcessRejectsDeviceErrorOutput(t *testing.T) {
	d := ciscoDriver(t)
	if _, err := d.Process(d.Outputs[0], "% Invalid input detected at '^' marker.\n"); err == nil {
		t.Fatal("expected error")
	}
}

func TestProcessErrorDoesNotEchoDeviceOutput(t *testing.T) {
	d := ciscoDriver(t)
	_, err := d.Process(d.Outputs[0], "secret-token-in-output\n% Invalid input\n")
	if err == nil || strings.Contains(err.Error(), "secret-token-in-output") {
		t.Fatalf("error must not contain device output: %v", err)
	}
}

func TestPEMPrivateKeyAlwaysMasked(t *testing.T) {
	dir := t.TempDir()
	def := `
name: plain
prompt: '#\s*$'
outputs: [{path: cfg, command: show}]
`
	if err := os.WriteFile(filepath.Join(dir, "plain.yaml"), []byte(def), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := driver.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := reg.Get("plain")
	in := "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIEsecretbody\nmoresecret\n-----END RSA PRIVATE KEY-----\nb\n"
	out, err := d.Process(d.Outputs[0], in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "secretbody") || strings.Contains(out, "moresecret") {
		t.Fatalf("private key leaked:\n%s", out)
	}
	if !strings.Contains(out, "-----BEGIN RSA PRIVATE KEY-----") || !strings.Contains(out, "\nb\n") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestJunosProcess(t *testing.T) {
	reg, err := driver.Load("")
	if err != nil {
		t.Fatal(err)
	}
	d, _ := reg.Get("junos")
	in := `## Last commit: 2026-11-09 12:00:00 JST by admin
version 21.4R3;
system {
    root-authentication {
        encrypted-password "$6$abc$def"; ## SECRET-DATA
    }
    login {
        user admin {
            authentication {
                encrypted-password "$6$ghi$jkl"; ## SECRET-DATA
            }
        }
    }
}
snmp {
    community s3cr3t {
        authorization read-only;
    }
}
security {
    ike {
        policy p1 {
            pre-shared-key ascii-text "$9$secretpsk"; ## SECRET-DATA
        }
    }
}

{master:0}
`
	out, err := d.Process(d.Outputs[0], in)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	for _, leaked := range []string{"$6$abc", "$6$ghi", "s3cr3t", "$9$secretpsk", "Last commit", "{master:0}"} {
		if strings.Contains(out, leaked) {
			t.Errorf("output still contains %q:\n%s", leaked, out)
		}
	}
	if !strings.Contains(out, "version 21.4R3;") {
		t.Errorf("output lost content:\n%s", out)
	}
}

func TestNECIXProcess(t *testing.T) {
	reg, err := driver.Load("")
	if err != nil {
		t.Fatal(err)
	}
	d, _ := reg.Get("nec_ix")
	in := `! NEC Portable Internetwork Core Operating System Software
! IX Series IX2215 (magellan-sec) Software, Version 10.2.16, RELEASE SOFTWARE
! Compiled Jan 01-Wed-2020 00:00:00 JST #2
! Current time Nov 11-Wed-2026 12:00:00 JST
!
hostname example-ix
username admin password hash 0123456789ABCDEF administrator
!
ike proposal ike-prop encryption aes-256 hash sha2-256 group 2048-bit
ike policy ike-policy peer any key s3cr3t-psk ike-prop
!
ppp profile isp
  authentication myname user@example.net
  authentication password user@example.net isp-password
!
snmp-agent ip community s3cr3t-comm
!
`
	out, err := d.Process(d.Outputs[0], in)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	for _, leaked := range []string{"0123456789ABCDEF", "s3cr3t-psk", "isp-password", "s3cr3t-comm", "Current time"} {
		if strings.Contains(out, leaked) {
			t.Errorf("output still contains %q:\n%s", leaked, out)
		}
	}
	if !strings.Contains(out, "hostname example-ix") {
		t.Errorf("output lost content:\n%s", out)
	}
}
