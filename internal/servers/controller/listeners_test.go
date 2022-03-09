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
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-secure-stdlib/configutil"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func TestStartListeners(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T)
		listeners  []*listenerutil.ListenerConfig
		assertions func(t *testing.T, c *Controller, apiAddrs []string, clusterAddr string)
	}{
		{
			name: "one api, one cluster listener",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "tcp",
					Purpose:    []string{"api"},
					Address:    "127.0.0.1:0",
					TLSDisable: true,
				},
				{
					Type:    "tcp",
					Purpose: []string{"cluster"},
					Address: "127.0.0.1:0",
				},
			},
			assertions: func(t *testing.T, c *Controller, apiAddrs []string, clusterAddr string) {
				rsp, err := http.Get("http://" + apiAddrs[0] + "/v1/auth-methods?scope_id=global")
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rsp.StatusCode)

				clusterGrpcDialNoError(t, c, "tcp", clusterAddr)
			},
		},
		{
			name: "multiple api, one cluster listeners",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "tcp",
					Purpose:    []string{"api"},
					Address:    "127.0.0.1:0",
					TLSDisable: true,
				},
				{
					Type:       "tcp",
					Purpose:    []string{"api"},
					Address:    "127.0.0.1:0",
					TLSDisable: true,
				},
				{
					Type:    "tcp",
					Purpose: []string{"cluster"},
					Address: "127.0.0.1:0",
				},
			},
			assertions: func(t *testing.T, c *Controller, apiAddrs []string, clusterAddr string) {
				for _, apiAddr := range apiAddrs {
					rsp, err := http.Get("http://" + apiAddr + "/v1/auth-methods?scope_id=global")
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, rsp.StatusCode)
				}

				clusterGrpcDialNoError(t, c, "tcp", clusterAddr)
			},
		},
		{
			name:  "one api (tls), one cluster listener",
			setup: testApiTlsSetup(t, "./boundary-startlistenerstest.cert", "./boundary-startlistenerstest.key"),
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:        "tcp",
					Purpose:     []string{"api"},
					Address:     "127.0.0.1:0",
					TLSCertFile: "./boundary-startlistenerstest.cert",
					TLSKeyFile:  "./boundary-startlistenerstest.key",
				},
				{
					Type:    "tcp",
					Purpose: []string{"cluster"},
					Address: "127.0.0.1:0",
				},
			},
			assertions: func(t *testing.T, c *Controller, apiAddrs []string, clusterAddr string) {
				client := testTlsHttpClient(t, "./boundary-startlistenerstest.cert")
				rsp, err := client.Get("https://" + apiAddrs[0] + "/v1/auth-methods?scope_id=global")
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rsp.StatusCode)

				clusterGrpcDialNoError(t, c, "tcp", clusterAddr)
			},
		},
		{
			name: "multiple api (tls), one cluster listener",
			setup: func(t *testing.T) {
				testApiTlsSetup(t, "./boundary-startlistenerstest0.cert", "./boundary-startlistenerstest0.key")(t)
				testApiTlsSetup(t, "./boundary-startlistenerstest1.cert", "./boundary-startlistenerstest1.key")(t)
			},
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:        "tcp",
					Purpose:     []string{"api"},
					Address:     "127.0.0.1:0",
					TLSCertFile: "./boundary-startlistenerstest0.cert",
					TLSKeyFile:  "./boundary-startlistenerstest0.key",
				},
				{
					Type:        "tcp",
					Purpose:     []string{"api"},
					Address:     "127.0.0.1:0",
					TLSCertFile: "./boundary-startlistenerstest1.cert",
					TLSKeyFile:  "./boundary-startlistenerstest1.key",
				},
				{
					Type:    "tcp",
					Purpose: []string{"cluster"},
					Address: "127.0.0.1:0",
				},
			},
			assertions: func(t *testing.T, c *Controller, apiAddrs []string, clusterAddr string) {
				for i, apiAddr := range apiAddrs {
					client := testTlsHttpClient(t, "./boundary-startlistenerstest"+strconv.Itoa(i)+".cert")
					rsp, err := client.Get("https://" + apiAddr + "/v1/auth-methods?scope_id=global")
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, rsp.StatusCode)
				}

				clusterGrpcDialNoError(t, c, "tcp", clusterAddr)
			},
		},
		{
			name: "one api, one cluster listener on unix sockets",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "unix",
					Purpose:    []string{"api"},
					Address:    "/tmp/boundary-listener-test-api.sock",
					TLSDisable: true,
				},
				{
					Type:    "unix",
					Purpose: []string{"cluster"},
					Address: "/tmp/boundary-listener-test-cluster.sock",
				},
			},
			assertions: func(t *testing.T, c *Controller, apiAddrs []string, clusterAddr string) {
				conn, err := net.Dial("unix", apiAddrs[0])
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

				clusterGrpcDialNoError(t, c, "unix", clusterAddr)
			},
		},
		{
			name: "multiple api, one cluster listener on unix sockets",
			listeners: []*listenerutil.ListenerConfig{
				{
					Type:       "unix",
					Purpose:    []string{"api"},
					Address:    "/tmp/boundary-listener-test-api.sock",
					TLSDisable: true,
				},
				{
					Type:       "unix",
					Purpose:    []string{"api"},
					Address:    "/tmp/boundary-listener-test-api2.sock",
					TLSDisable: true,
				},
				{
					Type:    "unix",
					Purpose: []string{"cluster"},
					Address: "/tmp/boundary-listener-test-cluster.sock",
				},
			},
			assertions: func(t *testing.T, c *Controller, apiAddrs []string, clusterAddr string) {
				for _, apiAddr := range apiAddrs {
					conn, err := net.Dial("unix", apiAddr)
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
				}

				clusterGrpcDialNoError(t, c, "unix", clusterAddr)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(t)
			}

			ctx, cancel := context.WithCancel(context.Background())

			tc := &TestController{t: t, ctx: ctx, cancel: cancel, opts: &TestControllerOpts{}}
			t.Cleanup(func() { tc.Shutdown() })

			conf := TestControllerConfig(t, ctx, tc, nil)
			conf.RawConfig.SharedConfig = &configutil.SharedConfig{Listeners: tt.listeners, DisableMlock: true}

			err := conf.SetupListeners(nil, conf.RawConfig.SharedConfig, []string{"api", "cluster"})
			require.NoError(t, err)

			c, err := New(ctx, conf)
			require.NoError(t, err)

			c.baseContext = ctx
			c.baseCancel = cancel

			err = c.startListeners()
			require.NoError(t, err)

			apiAddrs := make([]string, 0)
			for _, l := range c.apiListeners {
				apiAddrs = append(apiAddrs, l.Mux.Addr().String())
			}
			tt.assertions(t, c, apiAddrs, c.clusterListener.Mux.Addr().String())
		})
	}
}

func clusterGrpcDialNoError(t *testing.T, c *Controller, network, addr string) {
	grpcConn, err := grpc.Dial(addr,
		grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithTimeout(5*time.Second),
		grpc.WithContextDialer(clusterTestDialer(t, c, network)),
	)
	require.NoError(t, err)
	require.NoError(t, grpcConn.Close())
}

func testApiTlsSetup(t *testing.T, certPath, keyPath string) func(t *testing.T) {
	return func(t *testing.T) {
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
	}
}

func testTlsHttpClient(t *testing.T, filePath string) *http.Client {
	f, err := os.Open(filePath)
	require.NoError(t, err)

	certBytes, err := ioutil.ReadAll(f)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certBytes)

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool},
		},
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
		DNSNames:              []string{"/tmp/boundary-listener-test-cluster.sock"},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	return certBytes, pub, priv
}

func clusterTestDialer(t *testing.T, c *Controller, network string) func(context.Context, string) (net.Conn, error) {
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

		conn, err := tls.Dial(network, addr, &tls.Config{
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
