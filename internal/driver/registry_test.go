package driver_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whywaita/thatchbox/internal/driver"
	"github.com/whywaita/thatchbox/internal/testutil"
)

func TestRegistryNamesSorted(t *testing.T) {
	got := testutil.Registry(t).Names()
	if want := []string{"cisco_ios", "junos", "nec_ix"}; !slices.Equal(got, want) {
		t.Fatalf("Names = %q, want %q", got, want)
	}
}

func TestValidatePath(t *testing.T) {
	for _, ok := range []string{"running-config", "a/b", "a.b/c-d_e", "..a"} {
		if err := driver.ValidatePath(ok); err != nil {
			t.Errorf("ValidatePath(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/abs", "..", "../x", "a/../../x", "a/../b", "./a", "a/", "a//b", `a\b`, `C:\x`} {
		if err := driver.ValidatePath(bad); err == nil {
			t.Errorf("ValidatePath(%q) accepted", bad)
		}
	}
}

func TestDriverLoadIgnoresOtherFiles(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"README.md":    "not a driver",
		"notes.yml":    "name: [",
		"sub/x.yaml":   "name: [",
		"extra.yaml":   "name: extra\nprompt: '#$'\noutputs: [{path: a, command: show}]\n",
		"nested/.keep": "",
	} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reg, err := driver.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := reg.Get("extra"); !ok {
		t.Fatal("extra driver not loaded")
	}
	if len(reg.Names()) != 4 {
		t.Fatalf("Names = %q", reg.Names())
	}
}

func TestDriverLoadErrors(t *testing.T) {
	if _, err := driver.Load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing directory accepted")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("name: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := driver.Load(dir)
	if err == nil || !strings.Contains(err.Error(), "broken.yaml") {
		t.Fatalf("broken YAML: %v", err)
	}
}

func TestDriverParseRejects(t *testing.T) {
	const out = "outputs: [{path: a, command: show}]\n"
	cases := map[string]string{
		"no name":                   "prompt: '#$'\n" + out,
		"no prompt":                 "name: x\n" + out,
		"unknown field":             "name: x\nprompt: '#$'\npromt: x\n" + out,
		"enable without command":    "name: x\nprompt: '#$'\nenable: {when: '>$', password_prompt: 'Password:'}\n" + out,
		"enable without when":       "name: x\nprompt: '#$'\nenable: {command: enable, password_prompt: 'Password:'}\n" + out,
		"enable without pw prompt":  "name: x\nprompt: '#$'\nenable: {when: '>$', command: enable}\n" + out,
		"pager without pattern":     "name: x\nprompt: '#$'\npager: {send: ' '}\n" + out,
		"bad error regexp":          "name: x\nprompt: '#$'\nerror: '['\n" + out,
		"empty drop entry":          "name: x\nprompt: '#$'\ndrop: ['']\n" + out,
		"bad replace":               "name: x\nprompt: '#$'\nreplace: [{pattern: '(', with: x}]\n" + out,
		"bad mask block":            "name: x\nprompt: '#$'\nmask_blocks: [{begin: 'a'}]\n" + out,
		"output without command":    "name: x\nprompt: '#$'\noutputs: [{path: a}]\n",
		"output bad end":            "name: x\nprompt: '#$'\noutputs: [{path: a, command: s, end: '('}]\n",
		"output mask without group": "name: x\nprompt: '#$'\noutputs: [{path: a, command: s, mask: ['pw \\S+']}]\n",
		"unclean output path":       "name: x\nprompt: '#$'\noutputs: [{path: a//b, command: s}]\n",
		"not yaml":                  "{{",
	}
	for name, def := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := driver.Parse([]byte(def)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

const customDriver = `
name: custom
prompt: '^\S+#\s*$'
error: '^% '
drop: ['^! volatile']
replace:
  - {pattern: '^(uptime) \d+$', with: '$1 <removed>'}
mask:
  - 'key (?P<secret>\S+)'
mask_blocks:
  - {begin: '^certificate', end: '^ quit$'}
outputs:
  - path: config
    command: show config
    end: '^end$'
    drop: ['^ntp clock-period']
    replace: [{pattern: 'v(\d)\.\d+', with: 'v$1'}]
    mask: ['community (?P<secret>\S+)']
  - path: version
    command: show version
`

func TestProcessAppliesDriverAndOutputRules(t *testing.T) {
	d := testutil.ParseDriver(t, customDriver)
	raw := "\r\n\r\n! volatile line\r\nuptime 12345\r\nversion v2.17   \r\nntp clock-period 1\r\n" +
		"key k1 key k2\r\nsnmp community c1\r\ncertificate self\r\n AABB\r\n CCDD\r\n quit\r\nend\r\n\r\n"
	got, err := d.Process(d.Outputs[0], raw)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"uptime <removed>",
		"version v2",
		"key <masked> key <masked>",
		"snmp community <masked>",
		"certificate self",
		"<masked>",
		" quit",
		"end",
	}, "\n") + "\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	// Output-specific rules do not apply to other outputs.
	got, err = d.Process(d.Outputs[1], "ntp clock-period 1\ncommunity c1\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != "ntp clock-period 1\ncommunity c1\n" {
		t.Fatalf("output rules leaked: %q", got)
	}
}

func TestProcessUnterminatedMaskBlockMasksToEnd(t *testing.T) {
	d := testutil.ParseDriver(t, customDriver)
	got, err := d.Process(d.Outputs[1], "certificate self\n AABB\n CCDD\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != "certificate self\n<masked>\n" {
		t.Fatalf("got %q", got)
	}
}

func TestProcessEmptyAfterDrop(t *testing.T) {
	d := testutil.ParseDriver(t, customDriver)
	for _, raw := range []string{"", "\r\n\r\n", "! volatile\n\n"} {
		if _, err := d.Process(d.Outputs[1], raw); !errors.Is(err, driver.ErrEmpty) {
			t.Errorf("Process(%q) = %v, want ErrEmpty", raw, err)
		}
	}
}

func TestProcessDeviceErrorWinsOverDrop(t *testing.T) {
	d := testutil.ParseDriver(t, customDriver)
	if _, err := d.Process(d.Outputs[1], "% Invalid input\n"); !errors.Is(err, driver.ErrDeviceError) {
		t.Fatalf("want ErrDeviceError, got %v", err)
	}
}
