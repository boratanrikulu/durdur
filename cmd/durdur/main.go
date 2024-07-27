package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	if err := app().Run(os.Args); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func app() *cli.App {
	return &cli.App{
		Name:  "Durdur",
		Usage: "eBPF-powered L3/L4 packet dropper",
		Commands: []*cli.Command{
			AttachCmd(),
			DetachCmd(),
			DropCmd(),
			UndropCmd(),
			ListCmd(),
		},
	}
}
