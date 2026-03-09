// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package targets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	credstatic "github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	serverpb "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/session"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// dynamicToWorkerCredential converts the strongly typed credential.Dynamic into
// a session.Credential suitable for passing to a Boundary worker.
func dynamicToWorkerCredential(ctx context.Context, cred credential.Dynamic) (session.Credential, error) {
	const op = "targets.dynamicToWorkerCredential"
	var workerCred *serverpb.Credential
	switch c := cred.(type) {
	case credential.UsernamePasswordDomain:
		workerCred = &serverpb.Credential{
			Credential: &serverpb.Credential_UsernamePasswordDomain{
				UsernamePasswordDomain: &serverpb.UsernamePasswordDomain{
					Username: c.Username(),
					Password: string(c.Password()),
					Domain:   c.Domain(),
				},
			},
		}
	case credential.UsernamePassword:
		workerCred = &serverpb.Credential{
			Credential: &serverpb.Credential_UsernamePassword{
				UsernamePassword: &serverpb.UsernamePassword{
					Username: c.Username(),
					Password: string(c.Password()),
				},
			},
		}
	case credential.SshCertificate:
		workerCred = &serverpb.Credential{
			Credential: &serverpb.Credential_SshCertificate{
				SshCertificate: &serverpb.SshCertificate{
					Username:    c.Username(),
					PrivateKey:  string(c.PrivateKey()),
					Certificate: string(c.Certificate()),
				},
			},
		}
	case credential.SshPrivateKey:
		workerCred = &serverpb.Credential{
			Credential: &serverpb.Credential_SshPrivateKey{
				SshPrivateKey: &serverpb.SshPrivateKey{
					Username:             c.Username(),
					PrivateKey:           string(c.PrivateKey()),
					PrivateKeyPassphrase: string(c.PrivateKeyPassphrase()),
				},
			},
		}

	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unsupported credential %T", c))
	}

	data, err := proto.Marshal(workerCred)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("marshalling dynamic secret to proto"))
	}
	return data, nil
}

func dynamicToSessionCredential(ctx context.Context, cred credential.Dynamic) (*pb.SessionCredential, error) {
	const op = "targets.dynamicToSessionCredential"
	l := cred.Library()
	secret := cred.Secret()
	// TODO: Access the json directly from the vault response instead of re-marshalling it.
	jSecret, err := json.Marshal(secret)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("marshalling secret to json"))
	}
	var sSecret *structpb.Struct
	switch secret.(type) {
	case map[string]any:
		// In this case we actually have to re-decode it. The proto wrappers
		// choke on json.Number and at the time I'm writing this I don't
		// have time to write a walk function to dig through with reflect
		// and find all json.Numbers and replace them. So we eat the
		// inefficiency. So note that we are specifically _not_ using a
		// decoder with UseNumber here.
		var dSecret map[string]any
		if err := json.Unmarshal(jSecret, &dSecret); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("decoding json for proto marshaling"))
		}
		sSecret, err = structpb.NewStruct(dSecret)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("creating proto struct for secret"))
		}
	}

	var credType string
	var credData *structpb.Struct
	if l.CredentialType() != globals.UnspecifiedCredentialType {
		credType = string(l.CredentialType())

		switch c := cred.(type) {
		case credential.UsernamePasswordDomain:
			credData, err = handlers.ProtoToStruct(
				ctx,
				&pb.UsernamePasswordDomainCredential{
					Username: c.Username(),
					Password: string(c.Password()),
					Domain:   c.Domain(),
				},
			)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("creating proto struct for credential"))
			}

		case credential.UsernamePassword:
			credData, err = handlers.ProtoToStruct(
				ctx,
				&pb.UsernamePasswordCredential{
					Username: c.Username(),
					Password: string(c.Password()),
				},
			)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("creating proto struct for credential"))
			}

		case credential.PasswordOnly:
			credData, err = handlers.ProtoToStruct(
				ctx,
				&pb.PasswordCredential{
					Password: string(c.Password()),
				},
			)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("creating proto struct for credential"))
			}

		case credential.SshPrivateKey:
			credData, err = handlers.ProtoToStruct(
				ctx,
				&pb.SshPrivateKeyCredential{
					Username:             c.Username(),
					PrivateKey:           string(c.PrivateKey()),
					PrivateKeyPassphrase: string(c.PrivateKeyPassphrase()),
				},
			)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("creating proto struct for credential"))
			}

		default:
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unsupported credential %T", c))
		}
	}

	return &pb.SessionCredential{
		CredentialSource: &pb.CredentialSource{
			Id:                l.GetPublicId(),
			Name:              l.GetName(),
			Description:       l.GetDescription(),
			CredentialStoreId: l.GetStoreId(),
			Type:              globals.ResourceInfoFromPrefix(l.GetPublicId()).Subtype.String(),
			CredentialType:    credType,
		},
		Secret: &pb.SessionSecret{
			Raw:     base64.StdEncoding.EncodeToString(jSecret),
			Decoded: sSecret,
		},
		Credential: credData,
	}, nil
}

// staticToWorkerCredential converts the credential.Static into
// a session.Credential suitable for passing to a Boundary worker.
func staticToWorkerCredential(ctx context.Context, cred credential.Static) (session.Credential, error) {
	const op = "targets.staticToWorkerCredential"
	var workerCred *serverpb.Credential
	switch c := cred.(type) {
	case *credstatic.UsernamePasswordCredential:
		workerCred = &serverpb.Credential{
			Credential: &serverpb.Credential_UsernamePassword{
				UsernamePassword: &serverpb.UsernamePassword{
					Username: c.GetUsername(),
					Password: string(c.GetPassword()),
				},
			},
		}

	case *credstatic.UsernamePasswordDomainCredential:
		workerCred = &serverpb.Credential{
			Credential: &serverpb.Credential_UsernamePasswordDomain{
				UsernamePasswordDomain: &serverpb.UsernamePasswordDomain{
					Username: c.GetUsername(),
					Password: string(c.GetPassword()),
					Domain:   c.GetDomain(),
				},
			},
		}

	case *credstatic.SshPrivateKeyCredential:
		workerCred = &serverpb.Credential{
			Credential: &serverpb.Credential_SshPrivateKey{
				SshPrivateKey: &serverpb.SshPrivateKey{
					Username:             c.GetUsername(),
					PrivateKey:           string(c.GetPrivateKey()),
					PrivateKeyPassphrase: string(c.GetPrivateKeyPassphrase()),
				},
			},
		}

	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unsupported credential %T", c))
	}

	data, err := proto.Marshal(workerCred)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("marshalling static secret to proto"))
	}
	return data, nil
}

func staticToSessionCredential(ctx context.Context, cred credential.Static) (*pb.SessionCredential, error) {
	const op = "targets.staticToSessionCredential"

	var credType string
	var credData *structpb.Struct
	var secret map[string]any
	switch c := cred.(type) {
	case *credstatic.UsernamePasswordCredential:
		var err error
		credType = string(globals.UsernamePasswordCredentialType)
		credData, err = handlers.ProtoToStruct(
			ctx,
			&pb.UsernamePasswordCredential{
				Username: c.GetUsername(),
				Password: string(c.GetPassword()),
			},
		)
		secret = map[string]any{
			"username": c.GetUsername(),
			"password": string(c.GetPassword()),
		}
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("creating proto struct for username password credential"))
		}
	case *credstatic.UsernamePasswordDomainCredential:
		var err error
		credType = string(globals.UsernamePasswordDomainCredentialType)
		credData, err = handlers.ProtoToStruct(
			ctx,
			&pb.UsernamePasswordDomainCredential{
				Username: c.GetUsername(),
				Password: string(c.GetPassword()),
				Domain:   c.GetDomain(),
			},
		)
		secret = map[string]any{
			"username": c.GetUsername(),
			"password": string(c.GetPassword()),
			"domain":   c.GetDomain(),
		}
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("creating proto struct for username password domain credential"))
		}
	case *credstatic.PasswordCredential:
		var err error
		credType = string(globals.PasswordCredentialType)
		credData, err = handlers.ProtoToStruct(
			ctx,
			&pb.PasswordCredential{
				Password: string(c.GetPassword()),
			},
		)
		secret = map[string]any{
			"password": string(c.GetPassword()),
		}
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("creating proto struct for password credential"))
		}
	case *credstatic.SshPrivateKeyCredential:
		var err error
		credType = string(globals.SshPrivateKeyCredentialType)
		credData, err = handlers.ProtoToStruct(
			ctx,
			&pb.SshPrivateKeyCredential{
				Username:             c.GetUsername(),
				PrivateKey:           string(c.GetPrivateKey()),
				PrivateKeyPassphrase: string(c.GetPrivateKeyPassphrase()),
			},
		)
		secret = map[string]any{
			"username":    c.GetUsername(),
			"private_key": string(c.GetPrivateKey()),
		}
		if len(c.GetPrivateKeyPassphrase()) > 0 {
			secret["private_key_passphrase"] = string(c.GetPrivateKeyPassphrase())
		}
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("creating proto struct for ssh private key credential"))
		}
	case *credstatic.JsonCredential:
		var err error
		credType = string(globals.JsonCredentialType)
		object := map[string]any{}
		err = json.Unmarshal(c.GetObject(), &object)
		if err != nil {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "unmarshalling json")
		}

		credData, err = structpb.NewStruct(object)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("creating proto struct for json credential"))
		}
		secret = object

	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unsupported credential %T", c))
	}

	jSecret, err := json.Marshal(secret)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("marshalling static secret to json"))
	}
	sSecret, err := structpb.NewStruct(secret)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("creating proto struct for secret"))
	}

	return &pb.SessionCredential{
		CredentialSource: &pb.CredentialSource{
			Id:                cred.GetPublicId(),
			Name:              cred.GetName(),
			Description:       cred.GetDescription(),
			CredentialStoreId: cred.GetStoreId(),
			Type:              credstatic.Subtype.String(),
			CredentialType:    credType,
		},
		Secret: &pb.SessionSecret{
			Raw:     base64.StdEncoding.EncodeToString(jSecret),
			Decoded: sSecret,
		},
		Credential: credData,
	}, nil
}
