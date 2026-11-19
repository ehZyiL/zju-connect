//go:build !linux

package desktop

import "time"

// Other platforms have not enabled transparent alias capture yet.
func aliasNow() time.Time { return time.Now() }
