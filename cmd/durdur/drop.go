package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/boratanrikulu/durdur/internal/ebpf"
	"github.com/urfave/cli/v2"
)

func DropCmd() *cli.Command {
	return &cli.Command{
		Name:   "drop",
		Usage:  "",
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
			&cli.StringFlag{
				Name:     "interface",
				Aliases:  []string{"i"},
				Usage:    "network interface",
				Required: true,
			},
		},
	}
}

func drop(c *cli.Context) error {
	ifaceName := c.String("interface")
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup network iface %q: %s", ifaceName, err)
	}

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

	return ebpf.LoadAndRun(iface, toIPs, fromIPs)
}
