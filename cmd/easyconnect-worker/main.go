// easyconnect-worker is private to EasyConnect Hub. Credentials arrive only
// over inherited pipes, never arguments, environment variables or files.
package main

import (
	"io"
	"log"
	"os"

	"github.com/mythologyli/zju-connect/internal/desktop"
)

func main() {
	input, output := os.Stdin, os.Stdout
	// Upstream diagnostics include session tokens. Do not forward them to IPC
	// or persist them. The parent also discards the process's stderr.
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		os.Exit(1)
	}
	os.Stdout, os.Stderr = null, null
	log.SetOutput(io.Discard)
	os.Exit(desktop.Run(input, output))
}
