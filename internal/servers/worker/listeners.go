package worker

import (
	"errors"
	"fmt"

	"github.com/hashicorp/go-multierror"
)

func (w *Worker) startListeners() error {
	servers := make([]func(), 0, len(w.conf.Listeners))

	for _, ln := range w.conf.Listeners {
		var err error
		for _, purpose := range ln.Config.Purpose {
			switch purpose {
			case "api", "cluster":
				// Do nothing, in dev mode we might see it here
			case "worker-alpn-tls":
				if w.listeningAddress != "" {
					return errors.New("more than one listening address found")
				}
				w.listeningAddress = ln.Config.Address
				w.logger.Info("reporting listening address to controllers", "address", w.listeningAddress)
				// TODO: other stuff
				// TODO: once we have an actual listener, record in w.listeningAddress the actual address with port
			default:
				err = fmt.Errorf("unknown listener purpose %q", purpose)
			}
			if err != nil {
				return err
			}
		}
	}

	for _, s := range servers {
		s()
	}

	return nil
}

func (w *Worker) stopListeners() error {
	var retErr *multierror.Error
	for _, ln := range w.conf.Listeners {
		if ln.ALPNListener != nil {
			if err := ln.ALPNListener.Close(); err != nil {
				retErr = multierror.Append(retErr, err)
			}
		}

		if !w.conf.RawConfig.DevController {
			if err := ln.Mux.Close(); err != nil {
				retErr = multierror.Append(retErr, err)
			}
		}
	}
	return retErr.ErrorOrNil()
}
