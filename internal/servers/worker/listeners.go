package worker

import (
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
				// Do nothing, in a dev mode we might see it here
			case "worker-alpn-tls":
				// TODO
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
