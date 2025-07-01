// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/hashicorp/nodeenrollment"
	nodetls "github.com/hashicorp/nodeenrollment/tls"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/protobuf/proto"
)

// getTlsConfigForClient produces a TLS configuration that can handle credential
// fetching and node authentication. It is intended to be used as part of a
// tls.Config.GetConfigForClient function. It is usable for this purpose as-is,
// or it can be chained to from an existing GetConfigForClient function.
//
// If there is no ALPN proto handled by this library, the listener's base TLS
// configuration will be chained to.
//
// Supported options: WithStorageWrapper (passed through to
// LoadRootCertificate), WithRandReader (passed through to ServerConfig and
// GenerateServerCertificates)
func (l *InterceptingListener) getTlsConfigForClient(clientInfo *ClientInfo) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	const op = "nodeenrollment.protocol.(InterceptingListener).getTlsConfigForClient"

	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		var trimmedProtos []string
		// Copy client next proto information to returned value
		if len(hello.SupportedProtos) > 0 {
			trimmedProtos = make([]string, len(hello.SupportedProtos))
			// If we have a certificate selector in NextProtos, pull it out and remove it from the list
			// of protos, as it's only for internal routing use
			for _, proto := range hello.SupportedProtos {
				if strings.HasPrefix(proto, nodeenrollment.CertificatePreferenceV1Prefix) {
					continue
				}
				trimmedProtos = append(trimmedProtos, proto)
			}
			clientInfo.nextProtos = trimmedProtos
		}

		// log.Println("incoming server name", hello.ServerName)

		// If they aren't announcing support, return the base configuration
		if !nodeenrollment.ContainsKnownAlpnProto(trimmedProtos...) {
			if l.baseTlsConf == nil {
				return nil, fmt.Errorf("(%s) no base tls configuration and no library next proto", op)
			}
			if l.baseTlsConf.GetConfigForClient != nil {
				return l.baseTlsConf.GetConfigForClient(hello)
			}
			return l.baseTlsConf, nil
		}

		serverCertsReq := new(types.GenerateServerCertificatesRequest)
		var protoToReturn string
		opt := l.options

		for _, p := range trimmedProtos {
			switch {
			// In either scenario, we will present a carefully curated server
			// certificate with information the node can use. How that certificate
			// is generated depends on the path.
			case strings.HasPrefix(p, nodeenrollment.FetchNodeCredsNextProtoV1Prefix):
				// Get the full string and pull out just the marshaled proto
				protoString, err := nodetls.CombineFromNextProtos(nodeenrollment.FetchNodeCredsNextProtoV1Prefix, hello.SupportedProtos)
				if err != nil {
					return nil, fmt.Errorf("(%s) error combining fetch node creds next proto value", op)
				}
				// Get the raw proto bytes
				reqBytes, err := base64.RawStdEncoding.DecodeString(protoString)
				if err != nil {
					return nil, fmt.Errorf("(%s) error base64-decoding fetch node creds next proto value", op)
				}
				// Decode the proto into the request
				req := new(types.FetchNodeCredentialsRequest)
				if err := proto.Unmarshal(reqBytes, req); err != nil {
					return nil, fmt.Errorf("(%s) error unmarshaling common name value: %w", op, err)
				}
				// This will return a response either with Authorized false and no
				// other data or Authorized true and encrypted values
				fetchResp, err := l.fetchCredsFn(l.ctx, l.storage, req, l.options...)
				if err != nil {
					return nil, fmt.Errorf("(%s) error handling fetch creds: %w", op, err)
				}

				// This is a bit redundant with the fetch function above but we need
				// a few values
				var reqInfo types.FetchNodeCredentialsInfo
				if err := proto.Unmarshal(req.Bundle, &reqInfo); err != nil {
					return nil, fmt.Errorf("(%s) cannot unmarshal request info: %w", op, err)
				}

				switch {
				case fetchResp == nil || fetchResp.EncryptedNodeCredentials == nil:
					// In this case we're not authorized, use the standard
					// common name and we'll detect this on the fetch side. If
					// we try to marshal a nil value value we end up with a zero
					// length message, a zero-length base-64 message, and hit an
					// error later if we don't remember this when decoding. So
					// create an empty message as a canary.
					// log.Println("fetchResp was nil")
					fetchResp = new(types.FetchNodeCredentialsResponse)
					serverCertsReq.CommonName = nodeenrollment.CommonDnsName
					// Ensure that our server TLS will serve the cert with the common name
					opt = append(opt, nodeenrollment.WithServerName(nodeenrollment.CommonDnsName))

				default:
					// log.Println("fetchResp was not nil")
					fetchRespBytes, err := proto.Marshal(fetchResp)
					if err != nil {
						return nil, fmt.Errorf("(%s) error marshaling fetch response: %w", op, err)
					}
					// Have the response put into the common name
					serverCertsReq.CommonName = base64.RawStdEncoding.EncodeToString(fetchRespBytes)
					// log.Println("common name just after marshaling", serverCertsReq.CommonName)
					// Ensure that our server TLS will serve the cert with the common name
					opt = append(opt, nodeenrollment.WithServerName(nodeenrollment.CommonDnsName))
				}

				// We are returning either unauthorized or encrypted creds so we
				// don't want to validate the node's credentials -- it doesn't have
				// them yet!
				serverCertsReq.SkipVerification = true
				serverCertsReq.Nonce = reqInfo.Nonce
				serverCertsReq.CertificatePublicKeyPkix = reqInfo.CertificatePublicKeyPkix
				protoToReturn = p
				// This is a hint to the standard TLS verification function to just allow it
				opt = append(opt, nodeenrollment.WithAlpnProtoPrefix(nodeenrollment.FetchNodeCredsNextProtoV1Prefix))

			case strings.HasPrefix(p, nodeenrollment.AuthenticateNodeNextProtoV1Prefix):
				// Get the full string and pull out just the marshaled proto
				protoString, err := nodetls.CombineFromNextProtos(nodeenrollment.AuthenticateNodeNextProtoV1Prefix, hello.SupportedProtos)
				if err != nil {
					return nil, fmt.Errorf("(%s) error combining auth node next proto value", op)
				}
				// Get the raw proto bytes
				reqBytes, err := base64.RawStdEncoding.DecodeString(protoString)
				if err != nil {
					return nil, fmt.Errorf("(%s) error base64-decoding auth node next proto value", op)
				}
				// Decode the certs request
				if err := proto.Unmarshal(reqBytes, serverCertsReq); err != nil {
					return nil, fmt.Errorf("(%s) error unmarshaling common name value: %w", op, err)
				}
				protoToReturn = p

			default:
				continue
			}

			// If we're here we found one of our known protos so break out of
			// the for loop and finish
			break
		}

		// Generate a server-side certificate
		// log.Println("before fn, common name in req", serverCertsReq.CommonName)
		certResp, err := l.generateServerCertificatesFn(l.ctx, l.storage, serverCertsReq, opt...)
		if err != nil {
			return nil, fmt.Errorf("(%s) error generating server-side certificate: %w", op, err)
		}
		if certResp == nil {
			return nil, fmt.Errorf("(%s) nil response when generating server-side certificate", op)
		}
		// Copy state in
		clientInfo.clientState = certResp.ClientState

		// Ensure that the key we just verified from the signature is the one
		// presented by the client when we handshake
		opt = append(opt, nodeenrollment.WithExpectedPublicKey(serverCertsReq.CertificatePublicKeyPkix))

		tlsConf, err := nodetls.ServerConfig(l.ctx, certResp, opt...)
		if err != nil {
			return nil, fmt.Errorf("(%s) error generating root tls config: %w", op, err)
		}

		tlsConf.NextProtos = []string{protoToReturn}
		return tlsConf, nil
	}
}
