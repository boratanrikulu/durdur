package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "Durdur",
		Usage: "Durdur is a L4 package dropper.",
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
