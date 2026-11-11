// Command thatchbox backs up network device configurations to a git remote.
package main

import (
	"os"

	"github.com/whywaita/thatchbox/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stderr))
}
