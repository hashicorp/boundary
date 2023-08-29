package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	targetspb "github.com/hashicorp/boundary/api/internal/pbs/controller/api/resources/targets"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/mr-tron/base58"
	"go.uber.org/atomic"
	"google.golang.org/protobuf/proto"
)

type Client struct {
	tofuToken         string
	connectionsLeft   *atomic.Int32
	connsLeftCh       chan int32
	sessionAuthzData  *targetspb.SessionAuthorizationData
	expiration        time.Time
	ctx               context.Context
	cancel            context.CancelFunc
	transport         *http.Transport
	workerAddr        string
	listenIp          net.IP
	listenPort        int64
	listener          *net.TCPListener
	listenerAddr      *net.TCPAddr
	listenerCloseOnce *sync.Once
	connWg            *sync.WaitGroup
}

func NewClient(ctx context.Context, authzToken string, opt ...Option) (*Client, error) {
	opts, err := GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("could not parse options: %w", err)
	}

	p := &Client{
		listenerCloseOnce: new(sync.Once),
		connWg:            new(sync.WaitGroup),
	}

	p.tofuToken, err = base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("could not derive random bytes for tofu token: %w", err)
	}

	p.connectionsLeft = atomic.NewInt32(0)
	p.connsLeftCh = make(chan int32)

	host, port, err := net.SplitHostPort(opts.WithListenAddress)
	if err != nil {
		return nil, fmt.Errorf("could not successfully split host/port for listen address: %w", err)
	}
	p.listenIp = net.ParseIP(host)
	if p.listenIp == nil {
		return nil, errors.New("host not successfully parsed as an ip address")
	}
	p.listenPort, err = strconv.ParseInt(port, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("port not successfully parsed: %w", err)
	}

	marshaled, err := base58.FastBase58Decoding(authzToken)
	if err != nil {
		return nil, fmt.Errorf("unable to base58-decode authorization token: %w", err)
	}
	if len(marshaled) == 0 {
		return nil, errors.New("zero-length authorization information after decoding")
	}
	// FIXME: Do we want this SDK dependency? Maybe also return the data in JSON format?
	p.sessionAuthzData = new(targetspb.SessionAuthorizationData)
	if err := proto.Unmarshal(marshaled, p.sessionAuthzData); err != nil {
		return nil, fmt.Errorf("unable to unmarshal authorization data: %w", err)
	}
	if len(p.sessionAuthzData.WorkerInfo) == 0 {
		return nil, errors.New("no workers found in authorization data")
	}

	p.connectionsLeft.Store(p.sessionAuthzData.ConnectionLimit)
	p.workerAddr = p.sessionAuthzData.WorkerInfo[0].Address
	workerHost, _, err := net.SplitHostPort(p.workerAddr)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			workerHost = p.workerAddr
		} else {
			return nil, fmt.Errorf("error splitting worker adddress host/port: %w", err)
		}
	}

	tlsConf, err := ClientTlsConfig(p.sessionAuthzData, workerHost)
	if err != nil {
		return nil, fmt.Errorf("error creating TLS configuration: %w", err)
	}
	p.expiration = tlsConf.Certificates[0].Leaf.NotAfter

	// We don't _rely_ on client-side timeout verification but this prevents us
	// seeming to be ready for a connection that will immediately fail when we
	// try to actually make it
	p.ctx, p.cancel = context.WithDeadline(ctx, p.expiration)

	transport := cleanhttp.DefaultTransport()
	transport.DisableKeepAlives = false
	// This isn't/shouldn't used anyways really because the connection is
	// hijacked, just setting for completeness
	transport.IdleConnTimeout = 0
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &tls.Dialer{Config: tlsConf}
		return dialer.DialContext(ctx, network, addr)
	}
	p.transport = transport

	return p, nil
}

func (p *Client) Proxy() error {
	defer p.cancel()

	var err error
	p.listener, err = net.ListenTCP("tcp", &net.TCPAddr{
		IP:   p.listenIp,
		Port: int(p.listenPort),
	})
	if err != nil {
		return fmt.Errorf("unable to start listening: %w", err)
	}

	listenerCloseFunc := func() {
		// Forces the for loop to exit instead of spinning on errors
		p.connectionsLeft.Store(0)
		_ = p.listener.Close()
	}

	// Ensure it runs on any other return condition
	defer func() {
		p.listenerCloseOnce.Do(listenerCloseFunc)
	}()

	p.listenerAddr = p.listener.Addr().(*net.TCPAddr)

	p.connWg.Add(1)
	go func() {
		defer p.connWg.Done()
		for {
			listeningConn, err := p.listener.AcceptTCP()
			if err != nil {
				select {
				case <-p.ctx.Done():
					return
				default:
					// When this hits zero we trigger listener close so this
					// isn't actually an error condition
					if p.connectionsLeft.Load() == 0 {
						return
					}
					// TODO: Log/alert in some way?
					continue
				}
			}
			p.connWg.Add(1)
			go func() {
				defer listeningConn.Close()
				defer p.connWg.Done()
				wsConn, err := p.getWsConn()
				if err != nil {
					// TODO: Log/alert in some way?
				} else {
					if err := p.runTcpProxyV1(wsConn, listeningConn); err != nil {
						// TODO: Log/alert in some way?
					}
				}
			}()
		}
	}()

	timer := time.NewTimer(time.Until(p.expiration))
	p.connWg.Add(1)
	go func() {
		defer p.connWg.Done()
		defer p.listenerCloseOnce.Do(listenerCloseFunc)

		for {
			select {
			case <-p.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				return
			case connsLeft := <-p.connsLeftCh:
				p.connectionsLeft.Store(connsLeft)
				// TODO: Surface this to caller
				if connsLeft == 0 {
					return
				}
			}
		}
	}()

	p.connWg.Wait()

	return nil
}
