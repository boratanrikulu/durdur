package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/boratanrikulu/durdur/internal/ebpf"
	"github.com/urfave/cli/v2"
)

var (
	ErrInvalidUsage = errors.New("invalid usage")
)

func DropCmd() *cli.Command {
	return &cli.Command{
		Name:   "drop",
		Usage:  "Adds new rules to the maps",
		Action: drop,
		Flags:  dropUndropFlags(),
	}
}

func drop(c *cli.Context) error {
	srcs, dnss, err := dropUndropParams(c)
	if err != nil {
		return err
	}

	return ebpf.WrapForAttached(func(e *ebpf.EBPF) error {
		if len(srcs) > 0 {
			if err := e.DropSrc(srcs...); err != nil {
				return err
			}
		}
		if len(dnss) > 0 {
			if err := e.DropDNS(dnss...); err != nil {
				return err
			}
		}

		return nil
	})
}

func dropUndropParams(c *cli.Context) (srcIPs []net.IP, dnss []string, err error) {
	srcs := c.StringSlice("src")
	for _, src := range srcs {
		srcIPs = append(srcIPs, net.ParseIP(src))
	}

	dnss = c.StringSlice("dns")

	if len(srcIPs)+len(dnss) == 0 {
		err = fmt.Errorf("you need to specify at least 1 rule: %w", ErrInvalidUsage)
		return
	}

	return
}

func dropUndropFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "destination",
			Aliases: []string{"dst"},
			Usage:   "destination address value of an IPv4 packet",
		},
		&cli.StringSliceFlag{
			Name:    "source",
			Aliases: []string{"src"},
			Usage:   "source address value of an IPv4 packet",
		},
		&cli.StringSliceFlag{
			Name:    "dns",
			Aliases: []string{"d"},
			Usage:   "domain value of a DNS packet",
		},
	}
}
