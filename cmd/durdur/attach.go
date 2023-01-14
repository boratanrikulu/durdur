package main

import (
	"fmt"
	"net"
	"path/filepath"

	"github.com/boratanrikulu/durdur/internal/ebpf"

	"github.com/urfave/cli/v2"
)

func AttachCmd() *cli.Command {
	return &cli.Command{
		Name:   "attach",
		Usage:  "Attaches the program to the kernel",
		Action: attach,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "bpffs",
				Aliases: []string{"b"},
				Usage:   "bpffs location",
				Value:   "/sys/fs/bpf",
			},
			&cli.StringFlag{
				Name:     "interface",
				Aliases:  []string{"i"},
				Usage:    "network interface name",
				Required: true,
			},
		},
	}
}

func attach(c *cli.Context) error {
	ifaceName := c.String("interface")
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup network iface %q: %w", ifaceName, err)
	}

	ebpf.FS = filepath.Clean(c.String("bpffs"))

	return ebpf.Attach(iface)
}
