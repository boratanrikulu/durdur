package main

import (
	"errors"
	"net"

	"github.com/boratanrikulu/durdur/internal/ebpf"

	"github.com/urfave/cli/v2"
)

func DropCmd() *cli.Command {
	return &cli.Command{
		Name:   "drop",
		Usage:  "Add new IPs to the maps.",
		Action: drop,
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:    "to",
				Aliases: []string{"t"},
				Usage:   "destination ip address",
			},
			&cli.StringSliceFlag{
				Name:    "from",
				Aliases: []string{"f"},
				Usage:   "source ip address",
			},
		},
	}
}

func drop(c *cli.Context) error {
	tos := c.StringSlice("to")
	var toIPs []net.IP
	for _, to := range tos {
		toIPs = append(toIPs, net.ParseIP(to))
	}

	froms := c.StringSlice("from")
	var fromIPs []net.IP
	for _, from := range froms {
		fromIPs = append(fromIPs, net.ParseIP(from))
	}

	if len(toIPs)+len(fromIPs) == 0 {
		return errors.New("you need to specify atleast 1 ip")
	}

	return ebpf.Drop(toIPs, fromIPs)
}
