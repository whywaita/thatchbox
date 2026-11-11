// Package collect fetches a device's outputs over SSH or telnet using its
// driver.
package collect

import (
	"context"
	"fmt"

	"github.com/whywaita/thatchbox/internal/driver"
	"github.com/whywaita/thatchbox/internal/inventory"
	"github.com/whywaita/thatchbox/internal/shell"
	"github.com/whywaita/thatchbox/internal/sshdial"
	"github.com/whywaita/thatchbox/internal/telnet"
)

// Collector collects devices from an inventory.
type Collector struct {
	Inventory *inventory.Inventory
	Drivers   *driver.Registry
}

// secrets is a resolved credential.
type secrets struct {
	username, password, privateKey, passphrase, enable string
}

// Collect returns the processed output files of dev.
func (c *Collector) Collect(ctx context.Context, dev inventory.Device) (map[string][]byte, error) {
	drv, ok := c.Drivers.Get(dev.Driver)
	if !ok {
		return nil, fmt.Errorf("unknown driver %q", dev.Driver)
	}
	sec, err := c.resolve(dev.Credential)
	if err != nil {
		return nil, err
	}
	sess, err := c.open(ctx, dev, drv, sec)
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	files := make(map[string][]byte, len(drv.Outputs))
	for _, o := range drv.Outputs {
		raw, err := sess.Run(ctx, o.Command)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", o.Path, err)
		}
		text, err := drv.Process(o, raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", o.Path, err)
		}
		files[o.Path] = []byte(text)
	}
	return files, nil
}

// open connects with the device's transport and returns a logged-in shell.
func (c *Collector) open(ctx context.Context, dev inventory.Device, drv *driver.Driver, sec secrets) (*shell.Session, error) {
	if dev.Transport == inventory.TransportTelnet {
		conn, err := telnet.Dial(ctx, dev.Address, dev.Port)
		if err != nil {
			return nil, err
		}
		sess, err := shell.OpenLogin(ctx, conn, drv, shell.Login{Username: sec.username, Password: sec.password}, sec.enable)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return sess, nil
	}
	var jump *sshdial.Target
	if dev.Jump != "" {
		j := c.Inventory.JumpHosts[dev.Jump]
		jsec, err := c.resolve(j.Credential)
		if err != nil {
			return nil, fmt.Errorf("jump host %s: %w", dev.Jump, err)
		}
		jt := sshTarget(j.Address, j.Port, j.KnownHosts, j.SSH, jsec)
		jump = &jt
	}
	conn, err := sshdial.Open(ctx, sshTarget(dev.Address, dev.Port, dev.KnownHosts, dev.SSH, sec), jump)
	if err != nil {
		return nil, err
	}
	sess, err := shell.Open(ctx, conn, drv, sec.enable)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return sess, nil
}

func sshTarget(host string, port int, knownHosts string, algos inventory.SSH, sec secrets) sshdial.Target {
	return sshdial.Target{
		Host:                 host,
		Port:                 port,
		Username:             sec.username,
		Password:             sec.password,
		PrivateKey:           []byte(sec.privateKey),
		PrivateKeyPassphrase: sec.passphrase,
		KnownHosts:           knownHosts,
		Algorithms:           algos,
	}
}

// resolve reads the named credential's secrets.
func (c *Collector) resolve(credential string) (secrets, error) {
	cred := c.Inventory.Credentials[credential]
	var sec secrets
	for _, f := range []struct {
		field  string
		secret inventory.Secret
		dst    *string
	}{
		{"username", cred.Username, &sec.username},
		{"password", cred.Password, &sec.password},
		{"private_key", cred.PrivateKey, &sec.privateKey},
		{"private_key_passphrase", cred.PrivateKeyPassphrase, &sec.passphrase},
		{"enable_password", cred.EnablePassword, &sec.enable},
	} {
		v, err := f.secret.Resolve()
		if err != nil {
			return secrets{}, fmt.Errorf("credential %s.%s: %w", credential, f.field, err)
		}
		*f.dst = v
	}
	return sec, nil
}
