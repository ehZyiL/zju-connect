//go:build !windows

package desktop

// trimWorkingSet 在非 Windows 平台什么都不做：依靠 runtime.GC 和 debug.FreeOSMemory 归还内核。
func trimWorkingSet() {}
