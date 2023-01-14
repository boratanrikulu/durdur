package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "Durdur",
		Usage: "eBPF-powered L3/L4 packet dropper",
		Commands: []*cli.Command{
			AttachCmd(),
			DetachCmd(),
			DropCmd(),
			UndropCmd(),
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalln(err)
	}
}
