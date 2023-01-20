package main

import (
	"github.com/boratanrikulu/durdur/internal/ebpf"

	"github.com/urfave/cli/v2"
)

func UndropCmd() *cli.Command {
	return &cli.Command{
		Name:   "undrop",
		Usage:  "Deletes rules from the maps",
		Action: undrop,
		Flags:  dropUndropFlags(),
	}
}

func undrop(c *cli.Context) error {
	dsts, srcs, dnss, err := dropUndropParams(c)
	if err != nil {
		return err
	}

	e, err := ebpf.NewEBPFWithLink()
	if err != nil {
		return err
	}
	defer e.Close()

	return ebpf.WrapForAttached(func(e *ebpf.EBPF) error {
		if len(dsts) > 0 {
			if err := e.UndropDst(dsts...); err != nil {
				return err
			}
		}
		if len(srcs) > 0 {
			if err := e.UndropSrc(srcs...); err != nil {
				return err
			}
		}
		if len(dnss) > 0 {
			if err := e.UndropDNS(dnss...); err != nil {
				return err
			}
		}

		return nil
	})
}
