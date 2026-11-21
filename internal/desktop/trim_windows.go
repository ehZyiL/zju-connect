//go:build windows

package desktop

import "syscall"

// trimWorkingSet 让 Windows 把本进程的物理工作集换出去。
func trimWorkingSet() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("SetProcessWorkingSetSize")
	handle, err := syscall.GetCurrentProcess()
	if err != nil || handle == 0 {
		return
	}
	_, _, _ = proc.Call(uintptr(handle), ^uintptr(0), ^uintptr(0))
}
