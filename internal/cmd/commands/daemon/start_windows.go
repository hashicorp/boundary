// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package daemon

import (
	"context"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/util"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func processRunning(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p != nil
}

const windowsServiceName = "BoundaryDaemon"

// start will ensure this is the only daemon running and spin off a separate process.
func (s *StartCommand) start(ctx context.Context, cmd commander, srv server) error {
	const op = "daemon.(StartCommand).start"
	switch {
	case util.IsNil(ctx):
		return errors.New(ctx, errors.InvalidParameter, op, "context is missing")
	}

	dotPath, err := DefaultDotDirectory(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	logFilePath := filepath.Join(dotPath, logFileName)
	file, err := os.OpenFile(logFilePath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	// TODO: setup log rotation etc...
	srv.setupLogging(ctx, file)

	l, err := listener(ctx, dotPath)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return svc.Run(windowsServiceName, &service{srv: srv, l: l, cmd: cmd})
}

var cachedServiceManager *mgr.Mgr

func serviceManager() (*mgr.Mgr, error) {
	if cachedServiceManager != nil {
		return cachedServiceManager, nil
	}
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	cachedServiceManager = m
	return cachedServiceManager, nil
}

type service struct {
	ctx context.Context
	srv server
	cmd commander
	l   net.Listener
}

// Execute implements svc.Handler and installs/updates/uninstalls the boundary daemon service
func (s *service) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	const op = "daemon.(service).Execute"
	changes <- svc.Status{State: svc.StartPending}

	defer func() {
		changes <- svc.Status{State: svc.StopPending}
	}()

	go func() {
		s.srv.serve(s.ctx, s.cmd, s.l)
	}()

	// Only accept stop state change events.
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop}

	var uninstall bool
loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop:
				break loop
			case svc.Interrogate:
				changes <- c.CurrentStatus
			default:
				log.Printf("Unexpected service control request #%d", c)
			}
		}
	}

	changes <- svc.Status{State: svc.StopPending}

	s.srv.shutdown()

	if uninstall {
		if err := uninstallManager(); err != nil {
			event.WriteError(s.ctx, op, err)
		}
	}
	return false,
		windows.NO_ERROR
}

func uninstallManager() error {
	m, err := serviceManager()
	if err != nil {
		return err
	}
	service, err := m.OpenService(windowsServiceName)
	if err != nil {
		return err
	}
	service.Control(svc.Stop)
	err = service.Delete()
	err2 := service.Close()
	if err != nil {
		return err
	}
	return err2
}

func installManager(ctx context.Context) error {
	const op = "daemon.installManager"
	m, err := serviceManager()
	if err != nil {
		return err
	}
	path, err := os.Executable()
	if err != nil {
		return nil
	}

	// TODO: Do we want to bail if executable isn't being run from the right location?

	service, err := m.OpenService(windowsServiceName)
	if err == nil {
		status, err := service.Query()
		if err != nil {
			service.Close()
			return err
		}
		if status.State != svc.Stopped {
			service.Close()
			if status.State == svc.StartPending {
				// We were *just* started by something else, so return success here, assuming the other program
				// starting this does the right thing. This can happen when, e.g., the updater relaunches the
				// manager service and then invokes wireguard.exe to raise the UI.
				return nil
			}
			return errors.New(ctx, errors.Internal, op, "the service wasn't already stopped")
		}
		err = service.Delete()
		service.Close()
		if err != nil {
			return err
		}
		for {
			service, err = m.OpenService(windowsServiceName)
			if err != nil {
				break
			}
			service.Close()
			time.Sleep(time.Second / 3)
		}
	}

	config := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartManual,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  "Boundary Daemon",
	}

	service, err = m.CreateService(windowsServiceName, path, config, "daemon", "start")
	if err != nil {
		return err
	}
	service.Start()
	return service.Close()
}

var _ svc.Handler = (*service)(nil)
