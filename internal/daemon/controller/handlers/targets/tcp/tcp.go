// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package tcp

import (
	"context"
	"math"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/hashicorp/boundary/internal/target/tcp"
	tcpStore "github.com/hashicorp/boundary/internal/target/tcp/store"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
)

const (
	defaultPortField       = "attributes.default_port"
	defaultClientPortField = "attributes.default_client_port"
)

type attribute struct {
	*pb.TcpTargetAttributes
}

func (a *attribute) Options() []target.Option {
	var opts []target.Option
	if a.GetDefaultPort().GetValue() != 0 {
		opts = append(opts, target.WithDefaultPort(a.GetDefaultPort().GetValue()))
	}
	if a.GetDefaultClientPort().GetValue() != 0 {
		opts = append(opts, target.WithDefaultClientPort(a.GetDefaultClientPort().GetValue()))
	}
	return opts
}

func (a *attribute) Vet() map[string]string {
	badFields := map[string]string{}
	if a.GetDefaultPort() == nil {
		badFields[defaultPortField] = "This field is required."
	} else {
		if a.GetDefaultPort().GetValue() == 0 {
			badFields[defaultPortField] = "This field cannot be set to zero."
		}
		if a.GetDefaultPort().GetValue() > math.MaxUint16 {
			badFields[defaultPortField] = "Value is greater than maximum port number."
		}
	}
	if a.GetDefaultClientPort() != nil {
		if a.GetDefaultClientPort().GetValue() == 0 {
			badFields[defaultClientPortField] = "This field cannot be set to zero."
		}
		if a.GetDefaultClientPort().GetValue() > math.MaxUint16 {
			badFields[defaultClientPortField] = "Value is greater than maximum port number."
		}
	}
	return badFields
}

func (a *attribute) VetForUpdate(p []string) map[string]string {
	badFields := map[string]string{}
	if handlers.MaskContains(p, defaultPortField) {
		if a.GetDefaultPort() == nil {
			badFields[defaultPortField] = "This field is required."
		} else {
			if a.GetDefaultPort().GetValue() == 0 {
				badFields[defaultPortField] = "This cannot be set to zero."
			}
			if a.GetDefaultPort().GetValue() > math.MaxUint16 {
				badFields[defaultPortField] = "Value is greater than maximum port number."
			}
		}
	}
	if handlers.MaskContains(p, defaultClientPortField) && a.GetDefaultClientPort() != nil {
		if a.GetDefaultClientPort().GetValue() == 0 {
			badFields[defaultClientPortField] = "This cannot be set to zero."
		}
		if a.GetDefaultClientPort().GetValue() > math.MaxUint16 {
			badFields[defaultClientPortField] = "Value is greater than maximum port number."
		}
	}
	return badFields
}

func newAttribute(m any) targets.Attributes {
	a := &attribute{
		&pb.TcpTargetAttributes{},
	}
	if tcpAttr, ok := m.(*pb.Target_TcpTargetAttributes); ok {
		a.TcpTargetAttributes = tcpAttr.TcpTargetAttributes
	}
	return a
}

func setAttributes(t target.Target, out *pb.Target) error {
	if t == nil {
		return nil
	}

	attrs := &pb.Target_TcpTargetAttributes{
		TcpTargetAttributes: &pb.TcpTargetAttributes{},
	}
	if t.GetDefaultPort() > 0 {
		attrs.TcpTargetAttributes.DefaultPort = &wrappers.UInt32Value{Value: t.GetDefaultPort()}
	}
	if t.GetDefaultClientPort() > 0 {
		attrs.TcpTargetAttributes.DefaultClientPort = &wrappers.UInt32Value{Value: t.GetDefaultClientPort()}
	}

	out.Attrs = attrs
	return nil
}

func noopSessionValidation(context.Context, *session.Session) error { return nil }

func init() {
	var maskManager handlers.MaskManager
	var err error

	if maskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&tcpStore.Target{}, &store.TargetAddress{}},
		handlers.MaskSource{&pb.Target{}, &pb.TcpTargetAttributes{}},
	); err != nil {
		panic(err)
	}

	targets.Register(tcp.Subtype, maskManager, newAttribute, setAttributes, noopSessionValidation)
}
