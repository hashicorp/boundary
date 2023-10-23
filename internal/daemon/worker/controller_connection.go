// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	mathrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/daemon/cluster"
	"github.com/hashicorp/boundary/internal/daemon/cluster/handlers"
	"github.com/hashicorp/boundary/internal/daemon/worker/internal/metric"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/version"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/multihop"
	"github.com/hashicorp/nodeenrollment/protocol"
	"github.com/hashicorp/nodeenrollment/util/toggledlogger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/resolver"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

var HandleHcpbClusterId func(s string) string

// StartControllerConnections starts up the resolver and initiates controller
// connection client creation
func (w *Worker) StartControllerConnections() error {
	const op = "worker.(Worker).StartControllerConnections"
	initialAddrs := make([]string, 0, len(w.conf.RawConfig.Worker.InitialUpstreams))
	for _, addr := range w.conf.RawConfig.Worker.InitialUpstreams {
		switch {
		case strings.HasPrefix(addr, "/"):
			initialAddrs = append(initialAddrs, addr)
		default:
			host, port, err := net.SplitHostPort(addr)
			if err != nil && strings.Contains(err.Error(), globals.MissingPortErrStr) {
				host, port, err = net.SplitHostPort(net.JoinHostPort(addr, "9201"))
			}
			if err != nil {
				return fmt.Errorf("error parsing upstream address: %w", err)
			}
			initialAddrs = append(initialAddrs, net.JoinHostPort(host, port))
		}
	}

	if len(initialAddrs) == 0 {
		if w.conf.RawConfig.HcpbClusterId != "" && HandleHcpbClusterId != nil {
			clusterId, err := parseutil.ParsePath(w.conf.RawConfig.HcpbClusterId)
			if err != nil && !errors.Is(err, parseutil.ErrNotAUrl) {
				return fmt.Errorf("failed to parse HCP Boundary cluster ID:  %q: %w", clusterId, err)
			}
			clusterAddress := HandleHcpbClusterId(clusterId)
			initialAddrs = append(initialAddrs, clusterAddress)
			event.WriteSysEvent(w.baseContext, op, fmt.Sprintf("Setting HCP Boundary cluster address %s as upstream address", clusterAddress))
		} else {
			return errors.New(w.baseContext, errors.InvalidParameter, op, "no initial upstream addresses found")
		}
	}

	for _, ar := range w.addressReceivers {
		ar.InitialAddresses(initialAddrs)
	}
	if err := w.createClientConn(initialAddrs[0]); err != nil {
		return fmt.Errorf("error making client connection to upstream address %s: %w", initialAddrs[0], err)
	}
	return nil
}

// upstreamDialerFunc dials an upstream server. extraAlpnProtos can be provided
// to kms and pki connections and are used for identifying, on the server side,
// the intended purpose of the connection.  upstreamDialerFunc takes an optional
// stateProvidingFunction which, if the connection is made using the nodeenrollment
// library, sends the state provided by it to the server and can be retrieved
// from the resulting *protocol.Conn.
func (w *Worker) upstreamDialerFunc(extraAlpnProtos ...string) func(context.Context, string) (net.Conn, error) {
	const op = "worker.(Worker).upstreamDialerFunc"
	return func(ctx context.Context, addr string) (net.Conn, error) {
		var conn net.Conn
		eventLogger, err := event.NewHclogLogger(w.baseContext, w.conf.Eventer)
		if err != nil {
			event.WriteError(w.baseContext, op, err)
			return nil, errors.Wrap(w.baseContext, err, op)
		}
		// Give the log a prefix
		eventLogger = eventLogger.Named(fmt.Sprintf("workerauth_dialer"))
		// Wrap the log in a toggle so we can turn it on and off via config and
		// SIGHUP
		eventLogger = toggledlogger.NewToggledLogger(eventLogger, w.conf.WorkerAuthDebuggingEnabled)
		st, err := w.workerConnectionInfo(addr)
		if err != nil {
			event.WriteError(w.baseContext, op, err)
			return nil, errors.Wrap(w.baseContext, err, op)
		}
		switch {
		case w.conf.RawConfig.Worker.UseDeprecatedKmsAuthMethod:
			conn, err = w.v1KmsAuthDialFn(ctx, addr, extraAlpnProtos...)
		default:
			conn, err = protocol.Dial(
				ctx,
				w.WorkerAuthStorage,
				addr,
				nodeenrollment.WithLogger(eventLogger),
				nodeenrollment.WithState(st),
				nodeenrollment.WithStorageWrapper(w.conf.WorkerAuthStorageKms),
				nodeenrollment.WithRegistrationWrapper(w.conf.WorkerAuthKms),
				nodeenrollment.WithWrappingRegistrationFlowApplicationSpecificParams(st),
				nodeenrollment.WithExtraAlpnProtos(extraAlpnProtos),
				// If the activation token hasn't been populated, this won't do
				// anything, and it won't do anything if it's already been used
				nodeenrollment.WithActivationToken(w.conf.RawConfig.Worker.ControllerGeneratedActivationToken),
			)
			// No error and a valid connection means the WorkerAuthRegistrationRequest was populated
			// We can remove the stored workerAuthRequest file
			if err == nil && conn != nil {
				if w.conf.RawConfig.Worker.AuthStoragePath != "" {
					workerAuthReqFilePath := filepath.Join(w.conf.RawConfig.Worker.AuthStoragePath, base.WorkerAuthReqFile)
					// Intentionally ignoring any error removing this file
					_ = os.Remove(workerAuthReqFilePath)
				}
			}
		}
		switch {
		case err == nil:
			// Nothing

		case errors.Is(err, nodeenrollment.ErrNotAuthorized):
			switch w.conf.RawConfig.Worker.ControllerGeneratedActivationToken {
			case "":
				// We don't event in this case, because the function retries
				// often and will spam the logs while waiting on the user to
				// transfer the worker-generated request over
				return nil, errors.Wrap(w.baseContext, err, op)

			default:
				// In this case, event, so that the operator can understand that
				// it was rejected
				event.WriteError(w.baseContext, op, fmt.Errorf("controller rejected activation token as invalid"))
				return nil, errors.Wrap(w.baseContext, err, op)
			}

		default:
			event.WriteError(w.baseContext, op, err)
			return nil, errors.Wrap(w.baseContext, err, op)
		}

		if conn != nil {
			if w.everAuthenticated.Load() == authenticationStatusNeverAuthenticated {
				w.everAuthenticated.Store(authenticationStatusFirstAuthentication)
			}

			event.WriteSysEvent(w.baseContext, op, "worker has successfully authenticated")
		}

		return conn, err
	}
}

func (w *Worker) v1KmsAuthDialFn(ctx context.Context, addr string, extraAlpnProtos ...string) (net.Conn, error) {
	const op = "worker.(Worker).v1KmsAuthDialFn"
	tlsConf, authInfo, err := w.workerAuthTLSConfig(extraAlpnProtos...)
	if err != nil {
		return nil, fmt.Errorf("error creating tls config for worker auth: %w", err)
	}
	dialer := &net.Dialer{}
	var nonTlsConn net.Conn
	switch {
	case strings.HasPrefix(addr, "/"):
		nonTlsConn, err = dialer.DialContext(ctx, "unix", addr)
	default:
		nonTlsConn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to dial to upstream: %w", err)
	}
	tlsConn := tls.Client(nonTlsConn, tlsConf)
	written, err := tlsConn.Write([]byte(authInfo.ConnectionNonce))
	if err != nil {
		if err := nonTlsConn.Close(); err != nil {
			event.WriteError(w.baseContext, op, err, event.WithInfoMsg("error closing connection after writing failure"))
		}
		return nil, fmt.Errorf("unable to write connection nonce: %w", err)
	}
	if written != len(authInfo.ConnectionNonce) {
		if err := nonTlsConn.Close(); err != nil {
			event.WriteError(w.baseContext, op, err, event.WithInfoMsg("error closing connection after writing failure"))
		}
		return nil, fmt.Errorf("expected to write %d bytes of connection nonce, wrote %d", len(authInfo.ConnectionNonce), written)
	}
	return tlsConn, nil
}

func (w *Worker) createClientConn(addr string) error {
	const op = "worker.(Worker).createClientConn"

	var res resolver.Builder
	for _, v := range w.addressReceivers {
		if rec, ok := v.(*grpcResolverReceiver); ok {
			res = rec.Resolver
		}
	}
	if res == nil {
		return errors.New(w.baseContext, errors.Internal, op, "unable to find a resolver.Builder amongst the address receivers")
	}

	dialOpts := createDefaultGRPCDialOptions(res, w.upstreamDialerFunc())

	cc, err := grpc.DialContext(w.baseContext,
		fmt.Sprintf("%s:///%s", res.Scheme(), addr),
		dialOpts...,
	)
	if err != nil {
		return fmt.Errorf("error dialing controller for worker auth: %w", err)
	}

	w.GrpcClientConn = cc
	w.controllerMultihopConn.Store(multihop.NewMultihopServiceClient(cc))

	var producer handlers.UpstreamMessageServiceClientProducer
	producer = func(context.Context) (pbs.UpstreamMessageServiceClient, error) {
		return pbs.NewUpstreamMessageServiceClient(cc), nil
	}

	w.controllerUpstreamMsgConn.Store(&producer)

	go monitorUpstreamConnectionState(w.baseContext, cc, w.upstreamConnectionState)

	return nil
}

// createDefaultGRPCDialOptions creates grpc.DialOption using default options
func createDefaultGRPCDialOptions(res resolver.Builder, upstreamDialerFn func(context.Context, string) (net.Conn, error)) []grpc.DialOption {
	defaultTimeout := (time.Second + time.Nanosecond).String()
	defServiceConfig := fmt.Sprintf(`
	  {
		"loadBalancingConfig": [ { "round_robin": {} } ],
		"methodConfig": [
		  {
			"name": [],
			"timeout": %q,
			"waitForReady": true
		  }
		]
	  }
	  `, defaultTimeout)

	dialOpts := []grpc.DialOption{
		grpc.WithResolvers(res),
		grpc.WithUnaryInterceptor(metric.InstrumentClusterClient()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(math.MaxInt32)),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(math.MaxInt32)),
		grpc.WithContextDialer(upstreamDialerFn),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(defServiceConfig),
		// Don't have the resolver reach out for a service config from the
		// resolver, use the one specified as default
		grpc.WithDisableServiceConfig(),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  time.Second,
				Multiplier: 1.2,
				Jitter:     0.2,
				MaxDelay:   3 * time.Second,
			},
		}),
	}

	return dialOpts
}

func (w *Worker) workerAuthTLSConfig(extraAlpnProtos ...string) (*tls.Config, *base.WorkerAuthInfo, error) {
	var err error
	info := &base.WorkerAuthInfo{
		Name:            w.conf.RawConfig.Worker.Name,
		Description:     w.conf.RawConfig.Worker.Description,
		ProxyAddress:    w.conf.RawConfig.Worker.PublicAddr,
		BoundaryVersion: version.Get().VersionNumber(),
	}

	info.ConnectionNonce, err = w.nonceFn(20)
	if err != nil {
		return nil, nil, err
	}

	pubKey, privKey, err := ed25519.GenerateKey(w.conf.SecureRandomReader)
	if err != nil {
		return nil, nil, err
	}
	host, err := base62.Random(20)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:              []string{host},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          big.NewInt(mathrand.Int63()),
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().Add(globals.WorkerAuthNonceValidityPeriod),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certBytes, err := x509.CreateCertificate(w.conf.SecureRandomReader, template, template, pubKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	certPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	info.CertPEM = pem.EncodeToMemory(certPEMBlock)

	marshaledKey, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEMBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: marshaledKey,
	}
	info.KeyPEM = pem.EncodeToMemory(keyPEMBlock)

	// Marshal and encrypt
	marshaledInfo, err := json.Marshal(info)
	if err != nil {
		return nil, nil, err
	}
	encInfo, err := w.conf.WorkerAuthKms.Encrypt(w.baseContext, marshaledInfo)
	if err != nil {
		return nil, nil, err
	}
	marshaledEncInfo, err := proto.Marshal(encInfo)
	if err != nil {
		return nil, nil, err
	}
	b64alpn := base64.RawStdEncoding.EncodeToString(marshaledEncInfo)
	var nextProtos []string
	nextProtos = append(nextProtos, extraAlpnProtos...)
	var count int
	for i := 0; i < len(b64alpn); i += 230 {
		end := i + 230
		if end > len(b64alpn) {
			end = len(b64alpn)
		}
		nextProtos = append(nextProtos, fmt.Sprintf("v1workerauth-%02d-%s", count, b64alpn[i:end]))
		count++
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	// Build local tls config
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(cert)
	tlsCert, err := tls.X509KeyPair(info.CertPEM, info.KeyPEM)
	if err != nil {
		return nil, nil, err
	}
	tlsConfig := &tls.Config{
		ServerName:   host,
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      rootCAs,
		NextProtos:   nextProtos,
		MinVersion:   tls.VersionTLS13,
	}

	return tlsConfig, info, nil
}

// workerConnectionInfo returns the worker's cluster.WorkerConnectionInfo as
// a struct suitable to be used as the state field in a *protocol.Conn
func (w *Worker) workerConnectionInfo(addr string) (*structpb.Struct, error) {
	const op = "worker.(Worker).workerConnectionInfo"
	wci := &cluster.WorkerConnectionInfo{
		UpstreamAddress:  addr,
		BoundaryVersion:  version.Get().VersionNumber(),
		Name:             w.conf.RawConfig.Worker.Name,
		Description:      w.conf.RawConfig.Worker.Description,
		PublicAddr:       w.conf.RawConfig.Worker.PublicAddr,
		OperationalState: w.operationalState.Load().(server.OperationalState).String(),
	}
	if w.LastStatusSuccess() != nil && len(w.LastStatusSuccess().GetWorkerId()) > 0 {
		// even though we wont have the worker the first time we dial, any
		// redial attempts should result in the worker id being populated
		wci.WorkerId = w.LastStatusSuccess().GetWorkerId()
	}
	st, err := wci.AsConnectionStateStruct()
	if err != nil {
		return nil, errors.Wrap(w.baseContext, err, op, errors.WithMsg("getting worker state"))
	}
	return st, nil
}

// monitorUpstreamConnectionState listens for new state changes from grpc client
// connection and updates the state
func monitorUpstreamConnectionState(ctx context.Context, cc *grpc.ClientConn, connectionState *atomic.Value) {
	var state connectivity.State
	if v := connectionState.Load(); !util.IsNil(v) {
		state = v.(connectivity.State)
	}

	for cc.WaitForStateChange(ctx, state) {
		newState := cc.GetState()

		// if the client is shutdown, exit function
		if newState == connectivity.Shutdown {
			return
		}

		connectionState.Store(newState)

		time.Sleep(10 * time.Millisecond)
	}
}
