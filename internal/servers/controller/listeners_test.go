package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-secure-stdlib/configutil"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestStartListeners(t *testing.T) {
	tests := []struct {
		name                    string
		setup                   func(t *testing.T)
		listeners               []*listenerutil.ListenerConfig
		expStartListenersErr    bool
		expStartListenersErrMsg string
		assertions              func(t *testing.T, c *Controller)
	}{
		{
			name: "normal api listener",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "tcp",
					Purpose:    []string{"api"},
					Address:    "127.0.0.1:57850",
					TLSDisable: true,
				},
			},
			expStartListenersErr: false,
			assertions: func(t *testing.T, _ *Controller) {
				rsp, err := http.Get("http://127.0.0.1:57850/v1/auth-methods?scope_id=global")
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rsp.StatusCode)
			},
		},
		{
			name: "tls api listener",
			setup: func(t *testing.T) {
				certPath := "./boundary-startlistenerstest.cert"
				keyPath := "./boundary-startlistenerstest.key"
				t.Cleanup(func() {
					require.NoError(t, os.Remove(certPath))
					require.NoError(t, os.Remove(keyPath))
				})

				certBytes, _, priv := createTestCert(t)

				certFile, err := os.Create(certPath)
				require.NoError(t, err)
				require.NoError(t, pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}))
				require.NoError(t, certFile.Close())

				keyFile, err := os.Create(keyPath)
				require.NoError(t, err)

				marshaledKey, err := x509.MarshalPKCS8PrivateKey(priv)
				require.NoError(t, err)

				require.NoError(t, pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: marshaledKey}))
				require.NoError(t, keyFile.Close())
			},
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:        "tcp",
					Purpose:     []string{"api"},
					Address:     "127.0.0.1:56239",
					TLSDisable:  false,
					TLSCertFile: "./boundary-startlistenerstest.cert",
					TLSKeyFile:  "./boundary-startlistenerstest.key",
				},
			},
			expStartListenersErr: false,
			assertions: func(t *testing.T, _ *Controller) {
				f, err := os.Open("./boundary-startlistenerstest.cert")
				require.NoError(t, err)

				certBytes, err := ioutil.ReadAll(f)
				require.NoError(t, err)
				require.NoError(t, f.Close())

				certPool := x509.NewCertPool()
				certPool.AppendCertsFromPEM(certBytes)

				client := http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{RootCAs: certPool},
					},
				}

				rsp, err := client.Get("https://127.0.0.1:56239/v1/auth-methods?scope_id=global")
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rsp.StatusCode)
			},
		},
		{
			name: "api listener on unix socket",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "unix",
					Purpose:    []string{"api"},
					Address:    "/tmp/boundary-listener-test.sock",
					TLSDisable: true,
				},
			},
			expStartListenersErr: false,
			assertions: func(t *testing.T, _ *Controller) {
				conn, err := net.Dial("unix", "/tmp/boundary-listener-test.sock")
				require.NoError(t, err)

				cl := http.Client{
					Transport: &http.Transport{
						Dial: func(network, addr string) (net.Conn, error) { return conn, nil },
					},
				}
				rsp, err := cl.Get("http://randomdomain.boundary/v1/auth-methods?scope_id=global")
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rsp.StatusCode)

				require.NoError(t, conn.Close())
			},
		},
		{
			name: "api listener on multiple unix sockets",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "unix",
					Purpose:    []string{"api"},
					Address:    "/tmp/boundary-listener-test1.sock",
					TLSDisable: true,
				},
				{
					Type:       "unix",
					Purpose:    []string{"api"},
					Address:    "/tmp/boundary-listener-test2.sock",
					TLSDisable: true,
				},
			},
			expStartListenersErr: false,
			assertions: func(t *testing.T, _ *Controller) {
				for _, sockAddr := range []string{"/tmp/boundary-listener-test1.sock", "/tmp/boundary-listener-test2.sock"} {
					conn, err := net.Dial("unix", sockAddr)
					require.NoError(t, err)

					cl := http.Client{
						Transport: &http.Transport{
							Dial: func(network, addr string) (net.Conn, error) { return conn, nil },
						},
					}

					rsp, err := cl.Get("http://randomdomain.boundary/v1/auth-methods?scope_id=global")
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, rsp.StatusCode)
				}
			},
		},
		{
			name: "multiple api listeners",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "tcp",
					Purpose:    []string{"api"},
					Address:    "127.0.0.1:58943",
					TLSDisable: true,
				},
				{
					Type:       "tcp",
					Purpose:    []string{"api"},
					Address:    "127.0.0.1:58944",
					TLSDisable: true,
				},
			},
			expStartListenersErr: false,
			assertions: func(t *testing.T, _ *Controller) {
				rsp, err := http.Get("http://127.0.0.1:58943/v1/auth-methods?scope_id=global")
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rsp.StatusCode)

				rsp, err = http.Get("http://127.0.0.1:58944/v1/auth-methods?scope_id=global")
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rsp.StatusCode)
			},
		},
		{
			name: "normal cluster listener",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:    "tcp",
					Purpose: []string{"cluster"},
					Address: "127.0.0.1:61024",
				},
			},
			expStartListenersErr: false,
			assertions: func(t *testing.T, c *Controller) {
				conn, err := grpc.Dial("127.0.0.1:61024",
					grpc.WithInsecure(),
					grpc.WithBlock(),
					grpc.WithTimeout(5*time.Second),
					grpc.WithContextDialer(grpcTestDialer(t, c)),
				)
				require.NoError(t, err)
				require.NoError(t, conn.Close())
			},
		},
		{
			name: "multiple cluster listeners",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:    "tcp",
					Purpose: []string{"cluster"},
					Address: "127.0.0.1:34906",
				},
				{
					Type:    "tcp",
					Purpose: []string{"cluster"},
					Address: "127.0.0.1:34907",
				},
			},
			expStartListenersErr: false,
			assertions: func(t *testing.T, c *Controller) {
				for _, addr := range []string{"127.0.0.1:34906", "127.0.0.1:34907"} {
					conn, err := grpc.Dial(addr,
						grpc.WithInsecure(),
						grpc.WithBlock(),
						grpc.WithTimeout(5*time.Second),
						grpc.WithContextDialer(grpcTestDialer(t, c)),
					)
					require.NoError(t, err)
					require.NoError(t, conn.Close())
				}
			},
		},
		{
			name: "one api, one cluster listener",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "tcp",
					Purpose:    []string{"api"},
					Address:    "127.0.0.1:43646",
					TLSDisable: true,
				},
				{
					Type:       "tcp",
					Purpose:    []string{"cluster"},
					Address:    "127.0.0.1:43647",
					TLSDisable: true,
				},
			},
			expStartListenersErr: false,
			assertions: func(t *testing.T, c *Controller) {
				rsp, err := http.Get("http://127.0.0.1:43646/v1/auth-methods?scope_id=global")
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rsp.StatusCode)

				conn, err := grpc.Dial("127.0.0.1:43647",
					grpc.WithInsecure(),
					grpc.WithBlock(),
					grpc.WithTimeout(5*time.Second),
					grpc.WithContextDialer(grpcTestDialer(t, c)),
				)
				require.NoError(t, err)
				require.NoError(t, conn.Close())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(t)
			}

			ctx, cancel := context.WithCancel(context.Background())
			tc := &TestController{
				t:      t,
				ctx:    ctx,
				cancel: cancel,
				opts:   &TestControllerOpts{},
			}
			t.Cleanup(func() {
				tc.Shutdown()
			})

			conf := TestControllerConfig(t, ctx, tc, nil)
			conf.RawConfig.SharedConfig = &configutil.SharedConfig{Listeners: tt.listeners, DisableMlock: true}

			c, err := New(ctx, conf)
			require.NoError(t, err)

			c.baseContext = ctx
			c.baseCancel = cancel
			c.gatewayServer, c.gatewayTicket, err = newGatewayServer(ctx, c.IamRepoFn, c.AuthTokenRepoFn, c.ServersRepoFn, c.kms, c.conf.Eventer)
			require.NoError(t, err)

			require.NoError(t, c.conf.SetupListeners(nil, c.conf.RawConfig.SharedConfig, []string{"api", "cluster"}))

			err = c.startListeners(ctx)
			if tt.expStartListenersErr {
				require.EqualError(t, err, tt.expStartListenersErrMsg)
				return
			}

			require.NoError(t, err)
			tt.assertions(t, c)
		})
	}
}

func createTestCert(t *testing.T) ([]byte, ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          big.NewInt(0),
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().Add(5 * time.Minute),
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	return certBytes, pub, priv
}

func grpcTestDialer(t *testing.T, c *Controller) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		certBytes, _, priv := createTestCert(t)

		marshaledKey, err := x509.MarshalPKCS8PrivateKey(priv)
		require.NoError(t, err)

		nonce, err := base62.Random(20)
		require.NoError(t, err)

		info := base.WorkerAuthInfo{
			CertPEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}),
			KeyPEM:          pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: marshaledKey}),
			ConnectionNonce: nonce,
		}
		infoBytes, err := json.Marshal(info)
		require.NoError(t, err)

		encInfo, err := c.conf.WorkerAuthKms.Encrypt(ctx, infoBytes, nil)
		require.NoError(t, err)

		protoEncInfo, err := proto.Marshal(encInfo)
		require.NoError(t, err)

		b64alpn := base64.RawStdEncoding.EncodeToString(protoEncInfo)

		var nextProtos []string
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
		require.NoError(t, err)

		rootCAs := x509.NewCertPool()
		rootCAs.AddCert(cert)

		tlsCert, err := tls.X509KeyPair(info.CertPEM, info.KeyPEM)
		require.NoError(t, err)

		conn, err := tls.Dial("tcp", addr, &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			RootCAs:      rootCAs,
			NextProtos:   nextProtos,
			MinVersion:   tls.VersionTLS13,
		})
		require.NoError(t, err)

		_, err = conn.Write([]byte(nonce))
		require.NoError(t, err)

		return conn, nil
	}
}
