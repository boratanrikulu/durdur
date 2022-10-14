package main

import (
	"path/filepath"

	"github.com/boratanrikulu/durdur/internal/ebpf"

	"github.com/urfave/cli/v2"
)

func DetachCmd() *cli.Command {
	return &cli.Command{
		Name:   "detach",
		Usage:  "Detaches the program from the kernel.",
		Action: detach,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "bpffs",
				Aliases: []string{"b"},
				Usage:   "mounted bpffs location",
				Value:   "/sys/fs/bpf",
			},
		},
	}
}

func detach(c *cli.Context) error {
	ebpf.FS = filepath.Clean(c.String("bpffs"))

	return ebpf.Detach()
}
