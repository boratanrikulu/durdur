package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/boratanrikulu/durdur/internal/ebpf"

	qt "github.com/frankban/quicktest"
)

var (
	tIface = "eth0"

	tDNS = "echo.bora.sh"
	tIP  = "149.248.213.227"
)

type tCommand struct {
	input   string
	checker func(c *qt.C)
}

func TestE2E(t *testing.T) {
	c := qt.New(t)
	cli := app()

	tests := []struct {
		name         string
		commands     []tCommand
		wantErr      bool
		wantErrStr   string
		withoutClean bool
	}{
		{
			name: "just attach",
			commands: []tCommand{
				{input: fmt.Sprintf("attach -i %s", tIface)},
			},
		},
		{
			name: "drop dns",
			commands: []tCommand{
				{input: fmt.Sprintf("attach -i %s", tIface)},
				{
					input: fmt.Sprintf("drop --dns %s", tDNS),
					checker: func(c *qt.C) {
						ebpf.TDNSLookup(c, tDNS, false)
					},
				},
			},
		},
		{
			name: "drop ip",
			commands: []tCommand{
				{input: fmt.Sprintf("attach -i %s", tIface)},
				{
					input: fmt.Sprintf("drop --src %s", tIP),
					checker: func(c *qt.C) {
						ebpf.TTCPWrite(c, tIP+":443", false)
					},
				},
			},
		},
		{
			name: "undrop dns",
			commands: []tCommand{
				{input: fmt.Sprintf("attach -i %s", tIface)},
				{
					input: fmt.Sprintf("drop --dns %s", tDNS),
				},
				{
					input: fmt.Sprintf("undrop --dns %s", tDNS),
					checker: func(c *qt.C) {
						ebpf.TDNSLookup(c, tDNS, true)
					},
				},
			},
		},
		{
			name: "undrop ip",
			commands: []tCommand{
				{input: fmt.Sprintf("attach -i %s", tIface)},
				{
					input: fmt.Sprintf("drop --src %s", tIP),
					checker: func(c *qt.C) {
						ebpf.TTCPWrite(c, tIP+":443", false)
					},
				},
				{
					input: fmt.Sprintf("undrop --src %s", tIP),
					checker: func(c *qt.C) {
						ebpf.TTCPWrite(c, tIP+":443", true)
					},
				},
			},
		},
		{
			name: "drop, fail, at least 1 rule",
			commands: []tCommand{
				{input: fmt.Sprintf("attach -i %s", tIface)},
				{input: "drop"},
			},
			wantErr:    true,
			wantErrStr: ".* at least 1 rule.*",
		},
		{
			name: "undrop, fail, at least 1 rule",
			commands: []tCommand{
				{input: fmt.Sprintf("attach -i %s", tIface)},
				{input: "undrop"},
			},
			wantErr:    true,
			wantErrStr: ".* at least 1 rule.*",
		},
		{
			name: "detach, fail, non attach",
			commands: []tCommand{
				{input: "detach"},
			},
			withoutClean: true,
			wantErr:      true,
			wantErrStr:   ".* not attached to the interface",
		},
		{
			name: "attach, fail, no interface",
			commands: []tCommand{
				{input: fmt.Sprintf("attach -i %s", "nointerface")},
			},
			withoutClean: true,
			wantErr:      true,
			wantErrStr:   ".* no such network interface",
		},
	}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			if !test.withoutClean {
				c.Cleanup(func() {
					c.Assert(cli.Run(args("detach")), qt.IsNil)
				})
			}

			for i, command := range test.commands {
				err := cli.Run(args(command.input))
				if !test.wantErr {
					c.Assert(err, qt.IsNil)
				} else if i == len(test.commands)-1 { // Check err only for last command, for wantErr feature.
					c.Assert(err, qt.ErrorMatches, test.wantErrStr)
				}
				if command.checker != nil {
					command.checker(c)
				}
			}
		})
	}
}

func args(input string) []string {
	inputs := strings.Split(input, " ")
	args := os.Args[0:1]
	return append(args, inputs...)
}
