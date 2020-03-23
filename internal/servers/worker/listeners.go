package worker

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/helper/strutil"
)

func (c *Worker) startListeners() error {
	var retErr *multierror.Error
	servers := make([]func(), 0, len(c.conf.Listeners))
	for _, ln := range c.conf.Listeners {
		switch c.conf.RawConfig.DevController {
		case false:
			// TODO: We'll eventually need to configure HTTP listening here for
			// org-provided certificate handling, and configure the mux's
			// defaultproto for accepting client connections for ALPN-based
			// auth

		default:
			// TODO: We'll need to go through any listeners marked for api
			// usage and add our websocket handlers to the server. Eventually
			// we may want to make the config function able to handle arbitrary
			// ALPNs in a dynamic way, so that in dev mode we can also register
			// alpn mode client auth handling via the cluster ports.
			// TODO again because...I like that idea and don't want to forget
			// about it :-)
			// For now just testing out the ability to authorize via the ALPN handler
			if strutil.StrListContains(ln.Config.Purpose, "cluster") {
				tlsConf, err := c.workerAuthTLSConfig()
				if err != nil {
					retErr = multierror.Append(retErr, fmt.Errorf("error creating tls config for worker auth: %w", err))
					continue
				}
				if ln.ALPNListener != nil {
					conn, err := tls.Dial(ln.ALPNListener.Addr().Network(), ln.ALPNListener.Addr().String(), tlsConf)
					if err != nil {
						retErr = multierror.Append(retErr, fmt.Errorf("error dialing controller for worker auth: %w", err))
						continue
					}
					_, err = conn.Write([]byte("foo"))
					if err != nil {
						retErr = multierror.Append(retErr, fmt.Errorf("error writing test string to controller for worker auth: %w", err))
						continue
					}
					_, err = conn.Read(make([]byte, 3))
					if err != nil {
						retErr = multierror.Append(retErr, fmt.Errorf("error reading test string from controller for worker auth: %w", err))
						continue
					}
					c.logger.Info("done good writing/reading")
					conn.Close()
					newTLSConf, _ := c.workerAuthTLSConfig()
					tlsConf.Certificates = newTLSConf.Certificates
					conn, err = tls.Dial(ln.ALPNListener.Addr().Network(), ln.ALPNListener.Addr().String(), tlsConf)
					if err != nil {
						retErr = multierror.Append(retErr, fmt.Errorf("error dialing controller for worker auth: %w", err))
						continue
					}
					_, err = conn.Write([]byte("foo"))
					if err != nil {
						retErr = multierror.Append(retErr, fmt.Errorf("error writing test string to controller for worker auth: %w", err))
						continue
					}
					_, err = conn.Read(make([]byte, 3))
					if err == nil {
						retErr = multierror.Append(retErr, errors.New("expected error reading test string from controller for worker auth"))
						continue
					}
					c.logger.Info("done bad writing/reading")
					conn.Close()
				}
			}
		}
	}

	err := retErr.ErrorOrNil()
	if err != nil {
		return err
	}

	for _, s := range servers {
		s()
	}

	return nil
}

func (c *Worker) stopListeners() error {
	serverWg := new(sync.WaitGroup)
	for _, ln := range c.conf.Listeners {
		if c.conf.RawConfig.DevController {
			// These will get closed by the controller's dev instance
			continue
		}

		if ln.HTTPServer == nil {
			continue
		}
		localLn := ln
		serverWg.Add(1)
		go func() {
			shutdownKill, shutdownKillCancel := context.WithTimeout(c.baseContext, localLn.Config.MaxRequestDuration)
			defer shutdownKillCancel()
			defer serverWg.Done()
			localLn.HTTPServer.Shutdown(shutdownKill)
		}()
	}
	serverWg.Wait()

	var retErr *multierror.Error
	for _, ln := range c.conf.Listeners {
		if ln.ALPNListener != nil {
			if err := ln.ALPNListener.Close(); err != nil {
				retErr = multierror.Append(retErr, err)
			}
		}

		if !c.conf.RawConfig.DevController {
			if err := ln.Mux.Close(); err != nil {
				retErr = multierror.Append(retErr, err)
			}
		}
	}
	return retErr.ErrorOrNil()
}
