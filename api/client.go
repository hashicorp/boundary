// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/hashicorp/boundary/api/recovery"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	retryablehttp "github.com/hashicorp/go-retryablehttp"
	rootcerts "github.com/hashicorp/go-rootcerts"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"golang.org/x/time/rate"
)

const (
	EnvBoundaryAddr          = "BOUNDARY_ADDR"
	EnvBoundaryCACert        = "BOUNDARY_CACERT"
	EnvBoundaryCAPath        = "BOUNDARY_CAPATH"
	EnvBoundaryClientCert    = "BOUNDARY_CLIENT_CERT"
	EnvBoundaryClientKey     = "BOUNDARY_CLIENT_KEY"
	EnvBoundaryClientTimeout = "BOUNDARY_CLIENT_TIMEOUT"
	EnvBoundaryTLSInsecure   = "BOUNDARY_TLS_INSECURE"
	EnvBoundaryTLSServerName = "BOUNDARY_TLS_SERVER_NAME"
	EnvBoundaryMaxRetries    = "BOUNDARY_MAX_RETRIES"
	EnvBoundaryToken         = "BOUNDARY_TOKEN"
	EnvBoundaryRateLimit     = "BOUNDARY_RATE_LIMIT"
	EnvBoundarySRVLookup     = "BOUNDARY_SRV_LOOKUP"

	AsciiCastMimeType = "application/x-asciicast"
	StreamChunkSize   = 1024 * 64 // stream chuck buffer size
)

// Config is used to configure the creation of the client
type Config struct {
	// Addr is the address of the Boundary controller. This should be a
	// complete URL such as "http://boundary.example.com". If you need a custom
	// SSL cert or want to enable insecure mode, you need to specify a custom
	// HttpClient.
	Addr string

	// Token is the client token that reuslts from authentication and can be
	// used to make calls into Boundary
	Token string

	// RecoveryKmsWrapper is a wrapper used in the recovery KMS authentication
	// flow. If set, this will always be used to generate a new token value
	// per-call, regardless of any value set in Token.
	RecoveryKmsWrapper wrapping.Wrapper

	// HttpClient is the HTTP client to use. Boundary sets sane defaults for the
	// http.Client and its associated http.Transport created in DefaultConfig.
	// If you must modify Boundary's defaults, it is suggested that you start
	// with that client and modify as needed rather than start with an empty
	// client (or http.DefaultClient). Currently if the client is cloned the
	// same HttpClient is used.
	HttpClient *http.Client

	// TLSConfig contains TLS configuration information. After modifying these
	// values, ConfigureTLS should be called.
	TLSConfig *TLSConfig

	// Headers contains extra headers that will be added to any request
	Headers http.Header

	// MaxRetries controls the maximum number of times to retry when a 5xx
	// error occurs. Set to 0 to disable retrying. Defaults to 2 (for a total
	// of three tries).
	MaxRetries int

	// Timeout is for setting custom timeout parameter in the HttpClient
	Timeout time.Duration

	// The Backoff function to use; a default is used if not provided
	Backoff retryablehttp.Backoff

	// The CheckRetry function to use; a default is used if not provided
	CheckRetry retryablehttp.CheckRetry

	// Limiter is the rate limiter used by the client. If this pointer is nil,
	// then there will be no limit set. In contrast, if this pointer is set,
	// even to an empty struct, then that limiter will be used. Note that an
	// empty Limiter is equivalent blocking all events. Currently if the client
	// is cloned the same limiter is used.
	Limiter *rate.Limiter

	// OutputCurlString causes the actual request to return an error of type
	// *OutputStringError. Type asserting the error message will allow
	// fetching a cURL-compatible string for the operation.
	OutputCurlString bool

	// SRVLookup enables the client to lookup the host through DNS SRV lookup
	SRVLookup bool
}

// TLSConfig contains the parameters needed to configure TLS on the HTTP client
// used to communicate with Boundary.
type TLSConfig struct {
	// CACert is the path to a PEM-encoded CA cert file to use to verify the
	// Boundary server SSL certificate.
	CACert string

	// CAPath is the path to a directory of PEM-encoded CA cert files to verify
	// the Boundary server SSL certificate.
	CAPath string

	// ClientCert is the path to the certificate for Boundary communication
	ClientCert string

	// ClientKey is the path to the private key for Boundary communication
	ClientKey string

	// ServerName, if set, is used to set the SNI host when connecting via
	// TLS.
	ServerName string

	// Insecure enables or disables SSL verification
	Insecure bool
}

// RateLimitLinearJitterBackoff wraps the retryablehttp.LinearJitterBackoff.
// It first checks if the response status code is http.StatusTooManyRequests
// (HTTP Code 429) or http.StatusServiceUnavailable (HTTP Code 503). If it is
// and the response contains a Retry-After response header, it will wait the
// amount of time specified by the header. Otherwise, this calls
// LinearJitterBackoff.
// See: https://pkg.go.dev/github.com/hashicorp/go-retryablehttp#LinearJitterBackoff
func RateLimitLinearJitterBackoff(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
	if resp != nil {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			if s, ok := resp.Header["Retry-After"]; ok {
				if sleep, err := strconv.ParseInt(s[0], 10, 64); err == nil {
					return time.Second * time.Duration(sleep)
				}
			}
		}
	}
	return retryablehttp.LinearJitterBackoff(min, max, attemptNum, resp)
}

// DefaultConfig returns a default configuration for the client. It is
// safe to modify the return value of this function.
//
// The default Addr is http://127.0.0.1:9200, but this can be overridden by
// setting the `BOUNDARY_ADDR` environment variable.
//
// If an error is encountered, this will return nil.
func DefaultConfig() (*Config, error) {
	config := &Config{
		Addr:       "http://127.0.0.1:9200",
		HttpClient: cleanhttp.DefaultPooledClient(),
		Timeout:    time.Second * 60,
		TLSConfig:  &TLSConfig{},
	}

	transport := config.HttpClient.Transport.(*http.Transport)
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	config.Backoff = RateLimitLinearJitterBackoff
	config.MaxRetries = 2
	config.Headers = make(http.Header)

	// Read from environment last to ensure it takes precedence.
	if err := config.ReadEnvironment(); err != nil {
		return config, fmt.Errorf("failed to read environment: %w", err)
	}

	return config, nil
}

// ConfigureTLS takes a set of TLS configurations and applies those to the the
// HTTP client.
func (c *Config) ConfigureTLS() error {
	if c.HttpClient == nil {
		c.HttpClient = cleanhttp.DefaultPooledClient()
	}

	if c.HttpClient.Transport.(*http.Transport).TLSClientConfig == nil {
		c.HttpClient.Transport.(*http.Transport).TLSClientConfig = &tls.Config{}
	}
	clientTLSConfig := c.HttpClient.Transport.(*http.Transport).TLSClientConfig

	var clientCert tls.Certificate
	foundClientCert := false

	switch {
	case c.TLSConfig.ClientCert != "" && c.TLSConfig.ClientKey != "":
		var err error
		clientCert, err = tls.LoadX509KeyPair(c.TLSConfig.ClientCert, c.TLSConfig.ClientKey)
		if err != nil {
			return err
		}
		foundClientCert = true
	case c.TLSConfig.ClientCert != "" || c.TLSConfig.ClientKey != "":
		return fmt.Errorf("both client cert and client key must be provided")
	}

	if c.TLSConfig.CACert != "" || c.TLSConfig.CAPath != "" {
		rootConfig := &rootcerts.Config{
			CAFile: c.TLSConfig.CACert,
			CAPath: c.TLSConfig.CAPath,
		}
		if err := rootcerts.ConfigureTLS(clientTLSConfig, rootConfig); err != nil {
			return err
		}
	}

	if c.TLSConfig.Insecure {
		clientTLSConfig.InsecureSkipVerify = true
	}

	if foundClientCert {
		// We use this function to ignore the server's preferential list of
		// CAs, otherwise any CA used for the cert auth backend must be in the
		// server's CA pool
		clientTLSConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &clientCert, nil
		}
	}

	if c.TLSConfig.ServerName != "" {
		clientTLSConfig.ServerName = c.TLSConfig.ServerName
	}

	return nil
}

// setAddr parses a given string, setting the actual address to the base. Note
// that if a very malformed URL is passed in, this may not return what one
// expects. For now this is on purpose to avoid requiring error handling.
//
// This also removes any trailing "/v1"; we'll use that in our commands so we
// don't require it from users.
func (c *Config) setAddr(addr string) error {
	u, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("error parsing address: %w", err)
	}
	c.Addr = fmt.Sprintf("%s://%s", u.Scheme, u.Host)

	// If there is a v1 segment, elide everything after it. Do this only for
	// the last v1 segment in case it's part of the base path.
	if lastIndex := strings.LastIndex(u.Path, "v1/"); lastIndex != -1 {
		u.Path = u.Path[:lastIndex]
	}

	// Remove trailing or leading slashes
	path := strings.Trim(u.Path, "/")
	// Remove v1 in front or back (e.g. they could have
	// https://boundary.example.com/myinstall/v1 which would put it at the
	// back)
	path = strings.TrimPrefix(path, "v1")
	path = strings.TrimSuffix(path, "v1")
	// Finally check again to make sure any slashes are removed before we join
	// below
	path = strings.Trim(path, "/")

	if path != "" {
		c.Addr = fmt.Sprintf("%s/%s", c.Addr, path)
	}

	return nil
}

// ReadEnvironment reads configuration information from the environment. If
// there is an error, no configuration value is updated.
func (c *Config) ReadEnvironment() error {
	var envCACert string
	var envCAPath string
	var envClientCert string
	var envClientKey string
	var envInsecure bool
	var envServerName string

	// Parse the environment variables
	if v := os.Getenv(EnvBoundaryAddr); v != "" {
		c.Addr = v
	}

	if v := os.Getenv(EnvBoundaryToken); v != "" {
		c.Token = v
	}

	if v := os.Getenv(EnvBoundaryMaxRetries); v != "" {
		maxRetries, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return err
		}
		// maxRetries is a 32-bit unsigned integer stored inside an uint64.
		// c.MaxRetries is a signed integer that is at least 32 bits in size.
		// Check bounds against lowest denominator before casting.
		if maxRetries > math.MaxInt32 {
			return fmt.Errorf("max retries must be less than or equal to %d", math.MaxInt32)
		}
		c.MaxRetries = int(maxRetries)
	}

	if v := os.Getenv(EnvBoundarySRVLookup); v != "" {
		var err error
		lookup, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("could not parse %s", EnvBoundarySRVLookup)
		}
		c.SRVLookup = lookup
	}

	if t := os.Getenv(EnvBoundaryClientTimeout); t != "" {
		clientTimeout, err := parseutil.ParseDurationSecond(t)
		if err != nil {
			return fmt.Errorf("could not parse %q", EnvBoundaryClientTimeout)
		}
		c.Timeout = clientTimeout
	}

	if v := os.Getenv(EnvBoundaryRateLimit); v != "" {
		rateLimit, burstLimit, err := parseRateLimit(v)
		if err != nil {
			return err
		}
		c.Limiter = rate.NewLimiter(rate.Limit(rateLimit), burstLimit)
	}

	// TLS Config
	{
		var foundTLSConfig bool
		if v := os.Getenv(EnvBoundaryCACert); v != "" {
			foundTLSConfig = true
			envCACert = v
		}
		if v := os.Getenv(EnvBoundaryCAPath); v != "" {
			foundTLSConfig = true
			envCAPath = v
		}
		if v := os.Getenv(EnvBoundaryClientCert); v != "" {
			foundTLSConfig = true
			envClientCert = v
		}
		if v := os.Getenv(EnvBoundaryClientKey); v != "" {
			foundTLSConfig = true
			envClientKey = v
		}
		if v := os.Getenv(EnvBoundaryTLSInsecure); v != "" {
			foundTLSConfig = true
			var err error
			envInsecure, err = strconv.ParseBool(v)
			if err != nil {
				return fmt.Errorf("could not parse BOUNDARY_TLS_INSECURE")
			}
		}
		if v := os.Getenv(EnvBoundaryTLSServerName); v != "" {
			foundTLSConfig = true
			envServerName = v
		}
		// Set the values on the config
		// Configure the HTTP clients TLS configuration.
		if foundTLSConfig {
			c.TLSConfig = &TLSConfig{
				CACert:     envCACert,
				CAPath:     envCAPath,
				ClientCert: envClientCert,
				ClientKey:  envClientKey,
				ServerName: envServerName,
				Insecure:   envInsecure,
			}
			return c.ConfigureTLS()
		}
	}

	return nil
}

func parseRateLimit(val string) (rate float64, burst int, err error) {
	_, err = fmt.Sscanf(val, "%f:%d", &rate, &burst)
	if err != nil {
		rate, err = strconv.ParseFloat(val, 64)
		if err != nil {
			err = fmt.Errorf("%v was provided but incorrectly formatted", EnvBoundaryRateLimit)
		}
		burst = int(rate)
	}

	return rate, burst, err
}

// Client is the client to the Boundary API. Create a client with NewClient.
type Client struct {
	modifyLock sync.RWMutex
	config     *Config
}

// NewClient returns a new client for the given configuration.
//
// If the configuration is nil, Boundary will use configuration from
// DefaultConfig(), which is the recommended starting configuration.
//
// If the environment variable `BOUNDARY_TOKEN` is present, the token will be
// automatically added to the client. Otherwise, you must manually call
// `SetToken()`.
func NewClient(c *Config) (*Client, error) {
	def, err := DefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("error encountered setting up default configuration: %w", err)
	}

	if c == nil {
		c = def
	}

	if c.HttpClient == nil {
		c.HttpClient = def.HttpClient
	}
	if c.HttpClient.Transport == nil {
		c.HttpClient.Transport = def.HttpClient.Transport
	}
	if c.HttpClient.CheckRedirect == nil {
		// Ensure redirects are not automatically followed
		c.HttpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			// Returning this value causes the Go net library to not close the
			// response body and to nil out the error. Otherwise retry clients may
			// try three times on every redirect because it sees an error from this
			// function (to prevent redirects) passing through to it.
			return http.ErrUseLastResponse
		}
	}

	if c.Addr != "" {
		if err := c.setAddr(c.Addr); err != nil {
			return nil, err
		}
	}

	return &Client{
		config: c,
	}, nil
}

// Addr returns the current (parsed) address
func (c *Client) Addr() string {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()

	return c.config.Addr
}

// Sets the address of Boundary in the client. The format of address should
// be "<Scheme>://<Host>:<Port>". Setting this on a client will override the
// value of the BOUNDARY_ADDR environment variable.
func (c *Client) SetAddr(addr string) error {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	return c.config.setAddr(addr)
}

// SetTLSConfig sets the TLS parameters to use and calls ConfigureTLS
func (c *Client) SetTLSConfig(conf *TLSConfig) error {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()
	if conf == nil {
		return fmt.Errorf("nil configuration supplied to SetTLSConfig")
	}

	c.config.TLSConfig = conf
	return c.config.ConfigureTLS()
}

// SetLimiter will set the rate limiter for this client.  This method is
// thread-safe. rateLimit and burst are specified according to
// https://godoc.org/golang.org/x/time/rate#NewLimiter
func (c *Client) SetLimiter(rateLimit float64, burst int) {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	c.config.Limiter = rate.NewLimiter(rate.Limit(rateLimit), burst)
}

// SetMaxRetries sets the number of retries that will be used in the case of
// certain errors
func (c *Client) SetMaxRetries(retries int) {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	c.config.MaxRetries = retries
}

// SetCheckRetry sets the CheckRetry function to be used for future requests.
func (c *Client) SetCheckRetry(checkRetry retryablehttp.CheckRetry) {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	c.config.CheckRetry = checkRetry
}

// SetClientTimeout sets the client request timeout
func (c *Client) SetClientTimeout(timeout time.Duration) {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	c.config.Timeout = timeout
}

func (c *Client) SetOutputCurlString(curl bool) {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	c.config.OutputCurlString = curl
}

// Token gets the configured token.
func (c *Client) Token() string {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()

	return c.config.Token
}

// SetToken sets the token directly. This won't perform any auth
// verification, it simply sets the token properly for future requests.
func (c *Client) SetToken(token string) {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	c.config.Token = token
}

// RecoveryKmsWrapper gets the configured recovery KMS wrapper.
func (c *Client) RecoveryKmsWrapper() wrapping.Wrapper {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()

	return c.config.RecoveryKmsWrapper
}

// SetRecoveryKmsWrapper sets the wrapper used for the recovery workflow
func (c *Client) SetRecoveryKmsWrapper(wrapper wrapping.Wrapper) {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	c.config.RecoveryKmsWrapper = wrapper
}

// SetHeaders clears all previous headers and uses only the given
// ones going forward.
func (c *Client) SetHeaders(headers http.Header) {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()
	c.config.Headers = headers
}

// SetBackoff sets the backoff function to be used for future requests.
func (c *Client) SetBackoff(backoff retryablehttp.Backoff) {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	c.config.Backoff = backoff
}

// Clone creates a new client with the same configuration. Note that the same
// underlying http.Client is used; modifying the client from more than one
// goroutine at once may not be safe, so modify the client as needed and then
// clone.
func (c *Client) Clone() *Client {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()

	config := c.config

	newConfig := &Config{
		Addr:               config.Addr,
		Token:              config.Token,
		RecoveryKmsWrapper: config.RecoveryKmsWrapper,
		HttpClient:         config.HttpClient,
		Headers:            make(http.Header),
		MaxRetries:         config.MaxRetries,
		Timeout:            config.Timeout,
		Backoff:            config.Backoff,
		CheckRetry:         config.CheckRetry,
		Limiter:            config.Limiter,
		OutputCurlString:   config.OutputCurlString,
		SRVLookup:          config.SRVLookup,
	}
	if config.TLSConfig != nil {
		newConfig.TLSConfig = new(TLSConfig)
		*newConfig.TLSConfig = *config.TLSConfig
	}
	for k, v := range config.Headers {
		vSlice := make([]string, 0, len(v))
		vSlice = append(vSlice, v...)
		newConfig.Headers[k] = vSlice
	}

	return &Client{config: newConfig}
}

func copyHeaders(in http.Header) http.Header {
	ret := make(http.Header)
	for k, v := range in {
		ret[k] = append(ret[k], v...)
	}

	return ret
}

// NewRequest creates a new raw request object to query the Boundary controller
// configured for this client. This is an advanced method and generally
// doesn't need to be called externally.
func (c *Client) NewRequest(ctx context.Context, method, requestPath string, body any, opt ...Option) (*retryablehttp.Request, error) {
	if c == nil {
		return nil, fmt.Errorf("client is nil")
	}

	// Figure out what to do with the body. If it's already a reader it might
	// be marshaled or raw bytes in a reader, so pass it through. Otherwise
	// attempt JSON encoding and then pop in a bytes.Buffer.
	var rawBody any
	if body != nil {
		switch t := body.(type) {
		case io.ReadCloser, io.Reader:
			rawBody = t
		case []byte:
			rawBody = bytes.NewBuffer(t)
		default:
			b, err := json.Marshal(body)
			if err != nil {
				return nil, fmt.Errorf("error marshaling body: %w", err)
			}
			rawBody = bytes.NewBuffer(b)
		}
	}

	c.modifyLock.RLock()
	addr := c.config.Addr
	srvLookup := c.config.SRVLookup
	token := c.config.Token
	httpClient := c.config.HttpClient
	headers := copyHeaders(c.config.Headers)
	c.modifyLock.RUnlock()

	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(addr, "unix://") {
		socket := strings.TrimPrefix(addr, "unix://")
		transport := httpClient.Transport.(*http.Transport)
		transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, "unix", socket)
		}

		// Since the address points to a unix domain socket, the scheme in the
		// *URL would be set to `unix`. The *URL in the client is expected to
		// be pointing to the protocol used in the application layer and not to
		// the transport layer. Hence, setting the fields accordingly.
		u.Scheme = "http"
		u.Path = ""

		// Go 1.21.0 introduced strict host header validation for clients.
		// Using unix domain socket addresses in the Host header fails
		// this validation. https://go.dev/issue/61431 details this problem.
		// The error-on-domain-socket-host-header will be removed in a
		// future release, but in the meantime, we need to set it to something
		// that isn't the actual unix domain socket address. Following
		// Docker's lead (https://github.com/moby/moby/pull/45942),
		// use a localhost TLD.
		u.Host = "api.boundary.localhost"
	}

	host := u.Host
	// if SRV records exist (see
	// https://tools.ietf.org/html/draft-andrews-http-srv-02), lookup the SRV
	// record and take the highest match; this is not designed for
	// high-availability, just discovery Internet Draft specifies that the SRV
	// record is ignored if a port is given
	if u.Port() == "" && srvLookup {
		_, addrs, err := net.LookupSRV("http", "tcp", u.Hostname())
		if err != nil {
			return nil, fmt.Errorf("error performing SRV lookup of http:tcp:%s : %w", u.Hostname(), err)
		}
		if len(addrs) > 0 {
			host = net.JoinHostPort(addrs[0].Target, fmt.Sprintf("%d", addrs[0].Port))
		}
	}

	req := &http.Request{
		Method: method,
		URL: &url.URL{
			User:   u.User,
			Scheme: u.Scheme,
			Host:   host,
			Path:   path.Join(u.Path, "/v1/", requestPath),
		},
		Host: u.Host,
	}
	req.Header = headers
	req.Header.Set("authorization", "Bearer "+token)
	req.Header.Set("content-type", "application/json")
	if ctx != nil {
		req = req.Clone(ctx)
	}

	ret := &retryablehttp.Request{
		Request: req,
	}
	if err := ret.SetBody(rawBody); err != nil {
		return nil, fmt.Errorf("error setting the raw body of the request: %w", err)
	}

	return ret, nil
}

// Do takes a properly configured request and applies client configuration to
// it, returning the response.
func (c *Client) Do(r *retryablehttp.Request, opt ...Option) (*Response, error) {
	opts := getOpts(opt...)
	c.modifyLock.RLock()
	limiter := c.config.Limiter
	maxRetries := c.config.MaxRetries
	checkRetry := c.config.CheckRetry
	backoff := c.config.Backoff
	httpClient := c.config.HttpClient
	timeout := c.config.Timeout
	token := c.config.Token
	recoveryKmsWrapper := c.config.RecoveryKmsWrapper
	outputCurlString := c.config.OutputCurlString && !opts.withSkipCurlOuptut
	c.modifyLock.RUnlock()

	ctx := r.Context()

	if limiter != nil {
		if err := limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("error waiting on rate limiter: %w", err)
		}
	}

	// Sanity check the token before potentially erroring from the API
	idx := strings.IndexFunc(token, func(c rune) bool {
		return !unicode.IsPrint(c)
	})
	if idx != -1 {
		return nil, fmt.Errorf("configured Boundary token contains non-printable characters and cannot be used")
	}

	if outputCurlString {
		LastOutputStringError = &OutputStringError{Request: r}
		return nil, LastOutputStringError
	}

	if timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		// This dance is just to ignore vet warnings; we don't want to cancel
		// this as it will make reading the response body impossible
		_ = cancel
	}
	r.Request = r.Request.Clone(ctx)

	if backoff == nil {
		backoff = retryablehttp.LinearJitterBackoff
	}

	if recoveryKmsWrapper != nil {
		token, err := recovery.GenerateRecoveryToken(ctx, recoveryKmsWrapper)
		if err != nil {
			return nil, fmt.Errorf("error generating recovery KMS workflow token: %w", err)
		}
		r.Header.Set("authorization", "Bearer "+token)
	}

	if checkRetry == nil {
		checkRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
			if recoveryKmsWrapper != nil &&
				resp != nil &&
				resp.Request != nil {
				token, err := recovery.GenerateRecoveryToken(ctx, recoveryKmsWrapper)
				if err != nil {
					return false, fmt.Errorf("error generating recovery KMS workflow token: %w", err)
				}
				if resp.Request.Header == nil {
					resp.Request.Header = make(http.Header)
				}
				resp.Request.Header.Set("authorization", "Bearer "+token)
			}
			return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
		}
	}

	client := &retryablehttp.Client{
		HTTPClient:   httpClient,
		RetryWaitMin: 1000 * time.Millisecond,
		RetryWaitMax: 1500 * time.Millisecond,
		RetryMax:     maxRetries,
		Backoff:      backoff,
		CheckRetry:   checkRetry,
		ErrorHandler: retryablehttp.PassthroughErrorHandler,
	}

	result, err := client.Do(r)
	if result != nil && err == nil && result.StatusCode == http.StatusTemporaryRedirect {
		// Declare loc here to reuse previous error
		var loc *url.URL

		loc, err = result.Location()
		if err != nil {
			return nil, fmt.Errorf("error getting new location during redirect: %w", err)
		}

		// Ensure a protocol downgrade doesn't happen
		if r.URL.Scheme == "https" && loc.Scheme != "https" {
			return nil, errors.New("redirect would cause protocol downgrade")
		}

		// Update the request
		r.URL = loc

		result, err = client.Do(r)
	}

	if err != nil {
		if strings.Contains(err.Error(), "tls: oversized") {
			err = fmt.Errorf(
				"%w\n\n"+
					"This error usually means that the controller is running with TLS disabled\n"+
					"but the client is configured to use TLS. Please either enable TLS\n"+
					"on the server or run the client with -address set to an address\n"+
					"that uses the http protocol:\n\n"+
					"    boundary <command> -address http://<address>\n\n"+
					"You can also set the BOUNDARY_ADDR environment variable:\n\n\n"+
					"    BOUNDARY_ADDR=http://<address> boundary <command>\n\n"+
					"where <address> is replaced by the actual address to the controller.",
				err)
		}
		return nil, err
	}

	return &Response{resp: result}, nil
}
