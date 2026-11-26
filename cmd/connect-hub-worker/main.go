// connect-hub-worker is private to Connect Hub. Credentials arrive only
// over inherited pipes, never arguments, environment variables or files.
package main

import (
	"io"
	"log"
	"os"
	"runtime/debug"

	"github.com/mythologyli/zju-connect/internal/desktop"
)

func main() {
	// 针对 Worker 进程施加内存自律限制：
	// 软限制 64MB，GC 百分比调整为 75，避免多 Worker 堆内存膨胀
	debug.SetMemoryLimit(64 << 20)
	debug.SetGCPercent(75)

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
