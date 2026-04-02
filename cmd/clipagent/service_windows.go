//go:build windows

package main

import (
	"log"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

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

func platformMain() {
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
		err = svc.Run("DocVaultClipAgent", &clipService{})
		if err != nil {
			log.Fatalf("service failed: %v", err)
		}
		return
	}

	log.Println("Running in console mode (use 'install' to register as Windows service)")
	runMonitor()
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

	// Set auto-recovery: restart on failure (5s, 10s, 30s)
	actions := [3]windows.SC_ACTION{
		{Type: windows.SC_ACTION_RESTART, Delay: 5000},
		{Type: windows.SC_ACTION_RESTART, Delay: 10000},
		{Type: windows.SC_ACTION_RESTART, Delay: 30000},
	}
	failureActions := windows.SERVICE_FAILURE_ACTIONS{
		ResetPeriod:  60,
		ActionsCount: 3,
		Actions:      &actions[0],
	}
	if err := windows.ChangeServiceConfig2(s, windows.SERVICE_CONFIG_FAILURE_ACTIONS, (*byte)(unsafe.Pointer(&failureActions))); err != nil {
		log.Printf("warning: could not set recovery actions: %v", err)
	}

	log.Println("Service installed with auto-recovery. Start with: net start DocVaultClipAgent")
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
