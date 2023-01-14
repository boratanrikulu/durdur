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
		Usage:  "Add new rules to the maps",
		Action: drop,
		Flags:  dropUndropFlags(),
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

	dnss := c.StringSlice("dns")

	if len(toIPs)+len(fromIPs)+len(dnss) == 0 {
		return errors.New("you need to specify at least 1 rule")
	}

	return ebpf.Drop(toIPs, fromIPs, dnss)
}

func dropUndropFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "to",
			Aliases: []string{"t"},
			Usage:   "destination address value of an IPv4 packet",
		},
		&cli.StringSliceFlag{
			Name:    "from",
			Aliases: []string{"f"},
			Usage:   "source address value of an IPv4 packet",
		},
		&cli.StringSliceFlag{
			Name:    "dns",
			Aliases: []string{"d"},
			Usage:   "domain value of a DNS packet",
		},
	}
}
