package main

import (
	"fmt"

	"github.com/boratanrikulu/durdur/internal/ebpf"

	"github.com/urfave/cli/v2"
)

func ListCmd() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "List maps",
		Subcommands: []*cli.Command{
			{
				Name:   "src",
				Usage:  "List src map",
				Action: listSrc,
			},
			{
				Name:   "dns",
				Usage:  "List dns map",
				Action: listDNS,
			},
		},
	}
}

func listSrc(c *cli.Context) error {
	return ebpf.WrapForAttached(func(e *ebpf.EBPF) error {
		srcList, err := e.ListSrc()
		if err != nil {
			return err
		}
		fmt.Println(srcList) // TODO: fancy print.
		return nil
	})
}

func listDNS(c *cli.Context) error {
	return ebpf.WrapForAttached(func(e *ebpf.EBPF) error {
		srcList, err := e.ListDNS()
		if err != nil {
			return err
		}
		fmt.Println(srcList) // TODO: fancy print.
		return nil
	})
}
