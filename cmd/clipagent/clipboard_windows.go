//go:build windows

package main

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                  = windows.NewLazySystemDLL("user32.dll")
	procOpenClipboard       = user32.NewProc("OpenClipboard")
	procCloseClipboard      = user32.NewProc("CloseClipboard")
	procGetClipboardSeq     = user32.NewProc("GetClipboardSequenceNumber")
	procGetClipboardData    = user32.NewProc("GetClipboardData")
	procGetForegroundWindow = user32.NewProc("GetForegroundWindow")
	procGetWindowTextW      = user32.NewProc("GetWindowTextW")

	kernel32       = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalSize = kernel32.NewProc("GlobalSize")

	procIsClipboardFormatAvailable = user32.NewProc("IsClipboardFormatAvailable")
	procGetWindowThreadProcessId   = user32.NewProc("GetWindowThreadProcessId")

	psapi                  = windows.NewLazySystemDLL("psapi.dll")
	procGetModuleBaseNameW = psapi.NewProc("GetModuleBaseNameW")
)

const (
	cfUnicodeText = 13
	cfHDROP       = 15
	cfDIB         = 8
)

type windowsMonitor struct {
	lastSeq uint32
}

func newClipboardMonitor() ClipboardMonitor {
	return &windowsMonitor{}
}

func (m *windowsMonitor) Poll() *ClipboardSnapshot {
	seq := getClipboardSequence()
	if seq == m.lastSeq || seq == 0 {
		return nil
	}
	m.lastSeq = seq

	contentType, contentSize := getClipboardContent()
	if contentSize == 0 {
		return nil
	}

	return &ClipboardSnapshot{
		ContentType: contentType,
		ContentSize: contentSize,
		AppName:     getProcessNameFromWindow(),
		WindowTitle: getForegroundWindowTitle(),
	}
}

func getUsername() string {
	return os.Getenv("USERNAME")
}

func getClipboardSequence() uint32 {
	ret, _, _ := procGetClipboardSeq.Call()
	return uint32(ret)
}

func getClipboardContent() (string, int) {
	ret, _, _ := procOpenClipboard.Call(0)
	if ret == 0 {
		return "unknown", 0
	}
	defer procCloseClipboard.Call()

	// Check for file list first
	if r, _, _ := procIsClipboardFormatAvailable.Call(uintptr(cfHDROP)); r != 0 {
		data, _, _ := procGetClipboardData.Call(uintptr(cfHDROP))
		if data != 0 {
			size, _, _ := procGlobalSize.Call(data)
			return "files", int(size)
		}
	}

	// Check for images
	if r, _, _ := procIsClipboardFormatAvailable.Call(uintptr(cfDIB)); r != 0 {
		data, _, _ := procGetClipboardData.Call(uintptr(cfDIB))
		if data != 0 {
			size, _, _ := procGlobalSize.Call(data)
			return "image", int(size)
		}
	}

	// Fall back to text
	data, _, _ := procGetClipboardData.Call(uintptr(cfUnicodeText))
	if data == 0 {
		return "unknown", 0
	}
	size, _, _ := procGlobalSize.Call(data)
	return "text", int(size)
}

func getProcessNameFromWindow() string {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return "unknown"
	}

	var pid uint32
	procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	if pid == 0 {
		return "unknown"
	}

	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return "unknown"
	}
	defer windows.CloseHandle(handle)

	buf := make([]uint16, 260)
	n, _, _ := procGetModuleBaseNameW.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&buf[0])), 260)
	if n == 0 {
		return "unknown"
	}
	return windows.UTF16ToString(buf[:n])
}

func getForegroundWindowTitle() string {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return "unknown"
	}
	buf := make([]uint16, 256)
	procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 256)
	return windows.UTF16ToString(buf)
}

func clipboardProbe() (bool, string) {
	ret, _, err := procOpenClipboard.Call(0)
	if ret == 0 {
		if err != windows.ERROR_SUCCESS {
			return false, err.Error()
		}
		return false, "OpenClipboard returned 0"
	}
	procCloseClipboard.Call()
	return true, ""
}
