package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/urfave/cli/v2"
)

func write(c *cli.Context, format string, a ...any) error {
	_, err := io.WriteString(c.App.Writer, fmt.Sprintf(format, a...))
	return err
}

func marshalAndWrite(c *cli.Context, list any) error {
	b, err := json.Marshal(list)
	if err != nil {
		return fmt.Errorf("marshal src list: %w", err)
	}

	return write(c, string(b))
}
