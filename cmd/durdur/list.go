package main

import (
	"github.com/boratanrikulu/durdur/internal/ebpf"

	"github.com/urfave/cli/v2"
	"golang.org/x/exp/maps"
)

func ListCmd() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "List all blocked values",
		Subcommands: []*cli.Command{
			{
				Name:   "src",
				Usage:  "Lists all blocked source address values",
				Action: listSrc,
			},
			{
				Name:   "dns",
				Usage:  "Lists all blocked domain values",
				Action: listDNS,
			},
			{
				Name:   "all",
				Usage:  "Lists all blocked source addres and domain values",
				Action: listAll,
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

		return marshalAndWrite(c, &srcList)
	})
}

func listDNS(c *cli.Context) error {
	return ebpf.WrapForAttached(func(e *ebpf.EBPF) error {
		dnsList, err := e.ListDNS()
		if err != nil {
			return err
		}

		return marshalAndWrite(c, &dnsList)
	})
}

func listAll(c *cli.Context) error {
	return ebpf.WrapForAttached(func(e *ebpf.EBPF) error {
		srcList, err := e.ListSrc()
		if err != nil {
			return err
		}

		dnsList, err := e.ListDNS()
		if err != nil {
			return err
		}

		maps.Copy(srcList, dnsList)

		return marshalAndWrite(c, &srcList)
	})
}
