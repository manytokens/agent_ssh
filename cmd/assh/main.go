package main

import (
	"fmt"
	"os"

	"agent_ssh/internal/app"
	"agent_ssh/internal/platform"
	"agent_ssh/internal/toolproto"
)

func main() {
	if err := app.Main(os.Args[1:]); err != nil {
		fmt.Fprintln(platform.ConsoleWriter(os.Stderr), "assh:", err)
		os.Exit(toolproto.ExitCode(err))
	}
}
