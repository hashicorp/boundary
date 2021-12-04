package tcp

import (
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/targets"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/hashicorp/boundary/internal/target/tcp/store"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
)

type attribute struct {
	*pb.TcpTargetAttributes
}

func (a *attribute) Options() []target.Option {
	var opts []target.Option
	if a.GetDefaultPort().GetValue() != 0 {
		opts = append(opts, target.WithDefaultPort(a.GetDefaultPort().GetValue()))
	}
	return opts
}

func (a *attribute) Vet() map[string]string {
	badFields := map[string]string{}
	if a.GetDefaultPort() != nil && a.GetDefaultPort().GetValue() == 0 {
		badFields["attributes.default_port"] = "This optional field cannot be set to 0."
	}
	return badFields
}

func newAttribute(t target.Target) targets.Attributes {
	a := &attribute{
		&pb.TcpTargetAttributes{},
	}
	if t != nil {
		if t.GetDefaultPort() > 0 {
			a.DefaultPort = &wrappers.UInt32Value{Value: t.GetDefaultPort()}
		}
	}
	return a
}

func init() {
	var maskManager handlers.MaskManager
	var err error

	if maskManager, err = handlers.NewMaskManager(
		handlers.MaskDestination{&store.Target{}},
		handlers.MaskSource{&pb.Target{}, &pb.TcpTargetAttributes{}},
	); err != nil {
		panic(err)
	}

	targets.Register(tcp.Subtype, maskManager, newAttribute)
}
