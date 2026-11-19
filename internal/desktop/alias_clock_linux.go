package desktop

import (
	"golang.org/x/sys/unix"
	"time"
)

// Linux authorization expiry includes suspend and ignores wall-clock changes.
func aliasNow() time.Time {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts) != nil {
		return time.Time{}
	}
	return time.Unix(ts.Sec, ts.Nsec)
}
