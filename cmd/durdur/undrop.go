package main

import (
	"errors"
	"net"

	"github.com/boratanrikulu/durdur/internal/ebpf"

	"github.com/urfave/cli/v2"
)

func UndropCmd() *cli.Command {
	return &cli.Command{
		Name:   "undrop",
		Usage:  "Deletes rules from the maps.",
		Action: undrop,
		Flags:  dropUndropFlags(),
	}
}

func undrop(c *cli.Context) error {
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

	return ebpf.Undrop(toIPs, fromIPs, dnss)
}
