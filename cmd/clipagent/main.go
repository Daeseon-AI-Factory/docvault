package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
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
	cfHDROP       = 15  // file list
	cfBitmap      = 2   // bitmap image
	cfDIB         = 8   // device-independent bitmap
)

type ClipboardEvent struct {
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	Action      string `json:"action"`       // "copy" or "paste"
	Application string `json:"application"`   // source app (copy) or dest app (paste)
	ContentType string `json:"content_type"`  // "text", "files", "image"
	ContentSize int    `json:"content_size"`
	WindowTitle string `json:"window_title"`  // full window title for context
	Timestamp   string `json:"timestamp"`
}

func main() {
	// Check if running as Windows service
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("failed to determine if running as service: %v", err)
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			installService()
			return
		case "uninstall":
			uninstallService()
			return
		}
	}

	if isService {
		// Run as Windows service
		err = svc.Run("DocVaultClipAgent", &clipService{})
		if err != nil {
			log.Fatalf("service failed: %v", err)
		}
		return
	}

	// Run in console mode
	log.Println("Running in console mode (use 'install' to register as Windows service)")
	runMonitor()
}

// clipService implements svc.Handler for Windows Service Control Manager.
type clipService struct{}

func (s *clipService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	done := make(chan struct{})
	go func() {
		runMonitor()
		close(done)
	}()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				return false, 0
			case svc.Interrogate:
				status <- c.CurrentStatus
			}
		case <-done:
			return false, 0
		}
	}
}

func installService() {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("get executable path: %v", err)
	}

	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CREATE_SERVICE)
	if err != nil {
		log.Fatalf("open SCManager: %v", err)
	}
	defer windows.CloseServiceHandle(m)

	s, err := windows.CreateService(m,
		windows.StringToUTF16Ptr("DocVaultClipAgent"),
		windows.StringToUTF16Ptr("DocVault Clipboard Monitor"),
		windows.SERVICE_ALL_ACCESS,
		windows.SERVICE_WIN32_OWN_PROCESS,
		windows.SERVICE_AUTO_START,
		windows.SERVICE_ERROR_NORMAL,
		windows.StringToUTF16Ptr(exePath),
		nil, nil, nil, nil, nil,
	)
	if err != nil {
		log.Fatalf("create service: %v", err)
	}
	defer windows.CloseServiceHandle(s)

	log.Println("Service installed successfully. Start with: net start DocVaultClipAgent")
}

func uninstallService() {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		log.Fatalf("open SCManager: %v", err)
	}
	defer windows.CloseServiceHandle(m)

	s, err := windows.OpenService(m, windows.StringToUTF16Ptr("DocVaultClipAgent"), windows.SERVICE_ALL_ACCESS)
	if err != nil {
		log.Fatalf("open service: %v", err)
	}
	defer windows.CloseServiceHandle(s)

	if err := windows.DeleteService(s); err != nil {
		log.Fatalf("delete service: %v", err)
	}
	log.Println("Service uninstalled successfully.")
}

func runMonitor() {
	serverURL := os.Getenv("DOCVAULT_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://docvault.company.local:8080"
	}

	psk := os.Getenv("DOCVAULT_AGENT_PSK")
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")

	log.Printf("DocVault clipboard agent starting on %s (user: %s)", hostname, username)
	log.Printf("Reporting to %s", serverURL)

	client := &http.Client{Timeout: 10 * time.Second}

	// Enroll with server
	enrollAgent(client, serverURL, psk, hostname, username)

	// Graceful shutdown on SIGINT/SIGTERM
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	var lastSeq uint32
	var lastCopyApp string      // track which app did the copy
	var lastCopySize int        // size of last copy
	ticker := time.NewTicker(500 * time.Millisecond) // check more frequently
	defer ticker.Stop()

	for {
		select {
		case <-quit:
			log.Println("shutting down clipboard agent")
			return
		case <-ticker.C:
			seq := getClipboardSequence()
			if seq == lastSeq || seq == 0 {
				continue
			}
			lastSeq = seq

			contentType, contentSize := getClipboardContent()
			if contentSize == 0 {
				continue
			}

			fgTitle := getForegroundWindowTitle()
			fgApp := getProcessNameFromWindow()

			// This is a copy event (clipboard content changed while app is in foreground)
			lastCopyApp = fgApp
			lastCopySize = contentSize

			event := ClipboardEvent{
				Hostname:    hostname,
				Username:    username,
				Action:      "copy",
				Application: fgApp,
				ContentType: contentType,
				ContentSize: contentSize,
				WindowTitle: fgTitle,
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
			}

			go sendEvent(client, serverURL, psk, &event)

			// If copy happened in one app and user switches to another,
			// we'll detect paste by monitoring Ctrl+V in the next iteration.
			// For now, track paste via the next clipboard-consuming app.
			_ = lastCopyApp
			_ = lastCopySize
		}
	}
}

func enrollAgent(client *http.Client, serverURL, psk, hostname, username string) {
	payload, _ := json.Marshal(map[string]string{
		"hostname": hostname,
		"username": username,
		"source":   "clipboard",
	})

	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/enroll", bytes.NewReader(payload))
	if err != nil {
		log.Printf("enroll request error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if psk != "" {
		req.Header.Set("X-Agent-PSK", psk)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("enroll error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Println("enrolled successfully with server")
	} else {
		log.Printf("enrollment returned status %d", resp.StatusCode)
	}
}

func getClipboardSequence() uint32 {
	ret, _, _ := procGetClipboardSeq.Call()
	return uint32(ret)
}

func getClipboardContentSize() int {
	ret, _, _ := procOpenClipboard.Call(0)
	if ret == 0 {
		return 0
	}
	defer procCloseClipboard.Call()

	data, _, _ := procGetClipboardData.Call(uintptr(cfUnicodeText))
	if data == 0 {
		return 0
	}

	size, _, _ := procGlobalSize.Call(data)
	return int(size)
}

// getClipboardContent detects the clipboard content type and size.
func getClipboardContent() (contentType string, contentSize int) {
	ret, _, _ := procOpenClipboard.Call(0)
	if ret == 0 {
		return "unknown", 0
	}
	defer procCloseClipboard.Call()

	// Check for file list first (drag-drop / copy files)
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

// getProcessNameFromWindow returns the executable name of the foreground window's process.
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
	n, _, _ := procGetModuleBaseNameW.Call(
		uintptr(handle),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		260,
	)
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

func sendEvent(client *http.Client, serverURL, psk string, event *ClipboardEvent) {
	body, err := json.Marshal(event)
	if err != nil {
		log.Printf("marshal error: %v", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/events/clipboard", bytes.NewReader(body))
	if err != nil {
		log.Printf("request error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if psk != "" {
		req.Header.Set("X-Agent-PSK", psk)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("send error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("server returned %d", resp.StatusCode)
		return
	}

	fmt.Printf(".")
}
