package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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

	"github.com/hashicorp/errwrap"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	retryablehttp "github.com/hashicorp/go-retryablehttp"
	rootcerts "github.com/hashicorp/go-rootcerts"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	"golang.org/x/time/rate"
)

const EnvWatchtowerAddress = "WATCHTOWER_ADDR"
const EnvWatchtowerCACert = "WATCHTOWER_CACERT"
const EnvWatchtowerCAPath = "WATCHTOWER_CAPATH"
const EnvWatchtowerClientCert = "WATCHTOWER_CLIENT_CERT"
const EnvWatchtowerClientKey = "WATCHTOWER_CLIENT_KEY"
const EnvWatchtowerClientTimeout = "WATCHTOWER_CLIENT_TIMEOUT"
const EnvWatchtowerTLSInsecure = "WATCHTOWER_TLS_INSECURE"
const EnvWatchtowerTLSServerName = "WATCHTOWER_TLS_SERVER_NAME"
const EnvWatchtowerMaxRetries = "WATCHTOWER_MAX_RETRIES"
const EnvWatchtowerToken = "WATCHTOWER_TOKEN"
const EnvWatchtowerRateLimit = "WATCHTOWER_RATE_LIMIT"
const EnvWatchtowerSRVLookup = "WATCHTOWER_SRV_LOOKUP"

// Config is used to configure the creation of the client
type Config struct {
	// Address is the address of the Watchtower controller. This should be a
	// complete URL such as "http://watchtower.example.com". If you need a custom
	// SSL cert or want to enable insecure mode, you need to specify a custom
	// HttpClient.
	Address string

	// Token is the client token that reuslts from authentication and can be
	// used to make calls into Watchtower
	Token string

	// HTTPClient is the HTTP client to use. Watchtower sets sane defaults for
	// the http.Client and its associated http.Transport created in
	// DefaultConfig. If you must modify Watchtower's defaults, it is
	// suggested that you start with that client and modify as needed rather
	// than start with an empty client (or http.DefaultClient).
	HTTPClient *http.Client

	// TLSConfig contains TLS configuration information. After modifying these
	// values, ConfigureTLS should be called.
	TLSConfig *TLSConfig

	// Headers contains extra headers that will be added to any request
	Headers http.Header

	// MaxRetries controls the maximum number of times to retry when a 5xx
	// error occurs. Set to 0 to disable retrying. Defaults to 2 (for a total
	// of three tries).
	MaxRetries int

	// Timeout is for setting custom timeout parameter in the HTTPClient
	Timeout time.Duration

	// If there is an error when creating the configuration, this will be the
	// error
	Error error

	// The Backoff function to use; a default is used if not provided
	Backoff retryablehttp.Backoff

	// The CheckRetry function to use; a default is used if not provided
	CheckRetry retryablehttp.CheckRetry

	// Limiter is the rate limiter used by the client.
	// If this pointer is nil, then there will be no limit set.
	// In contrast, if this pointer is set, even to an empty struct,
	// then that limiter will be used. Note that an empty Limiter
	// is equivalent blocking all events.
	Limiter *rate.Limiter

	// OutputCurlString causes the actual request to return an error of type
	// *OutputStringError. Type asserting the error message will allow
	// fetching a cURL-compatible string for the operation.
	//
	// Note: It is not thread-safe to set this and make concurrent requests
	// with the same client. Cloning a client will not clone this value.
	OutputCurlString bool

	// SRVLookup enables the client to lookup the host through DNS SRV lookup
	SRVLookup bool
}

// TLSConfig contains the parameters needed to configure TLS on the HTTP client
// used to communicate with Watchtower.
type TLSConfig struct {
	// CACert is the path to a PEM-encoded CA cert file to use to verify the
	// Vault server SSL certificate.
	CACert string

	// CAPath is the path to a directory of PEM-encoded CA cert files to verify
	// the Vault server SSL certificate.
	CAPath string

	// ClientCert is the path to the certificate for Vault communication
	ClientCert string

	// ClientKey is the path to the private key for Vault communication
	ClientKey string

	// ServerName, if set, is used to set the SNI host when connecting via
	// TLS.
	ServerName string

	// Insecure enables or disables SSL verification
	Insecure bool
}

// DefaultConfig returns a default configuration for the client. It is
// safe to modify the return value of this function.
//
// The default Address is https://127.0.0.1:9200, but this can be overridden by
// setting the `WATCHTOWER_ADDR` environment variable.
//
// If an error is encountered, this will return nil.
func DefaultConfig() *Config {
	config := &Config{
		Address:    "https://127.0.0.1:9200",
		HTTPClient: cleanhttp.DefaultPooledClient(),
		Timeout:    time.Second * 60,
	}

	// We read the environment now; after DefaultClient returns we can override
	// values from command line flags, which should take precedence.
	if err := config.ReadEnvironment(); err != nil {
		config.Error = err
		return config
	}

	transport := config.HTTPClient.Transport.(*http.Transport)
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	config.Backoff = retryablehttp.LinearJitterBackoff
	config.MaxRetries = 2
	config.Headers = make(http.Header)

	return config
}

// ConfigureTLS takes a set of TLS configurations and applies those to the the
// HTTP client.
func (c *Config) ConfigureTLS() error {
	if c.HTTPClient == nil {
		c.HTTPClient = DefaultConfig().HTTPClient
	}
	clientTLSConfig := c.HTTPClient.Transport.(*http.Transport).TLSClientConfig

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

// ReadEnvironment reads configuration information from the environment. If
// there is an error, no configuration value is updated.
func (c *Config) ReadEnvironment() error {
	var envAddress string
	var envCACert string
	var envCAPath string
	var envClientCert string
	var envClientKey string
	var envClientTimeout time.Duration
	var envInsecure bool
	var envServerName string
	var envMaxRetries *uint64
	var envSRVLookup *bool
	var envToken string
	var limit *rate.Limiter
	var foundTLSConfig bool

	// Parse the environment variables
	if v := os.Getenv(EnvWatchtowerAddress); v != "" {
		envAddress = v
	}

	if v := os.Getenv(EnvWatchtowerToken); v != "" {
		envToken = v
	}

	if v := os.Getenv(EnvWatchtowerMaxRetries); v != "" {
		maxRetries, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return err
		}
		envMaxRetries = &maxRetries
	}
	if v := os.Getenv(EnvWatchtowerCACert); v != "" {
		foundTLSConfig = true
		envCACert = v
	}
	if v := os.Getenv(EnvWatchtowerCAPath); v != "" {
		foundTLSConfig = true
		envCAPath = v
	}
	if v := os.Getenv(EnvWatchtowerClientCert); v != "" {
		foundTLSConfig = true
		envClientCert = v
	}
	if v := os.Getenv(EnvWatchtowerClientKey); v != "" {
		foundTLSConfig = true
		envClientKey = v
	}

	if v := os.Getenv(EnvWatchtowerTLSInsecure); v != "" {
		foundTLSConfig = true
		var err error
		envInsecure, err = strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("could not parse WATCHTOWER_TLS_INSECURE")
		}
	}

	if v := os.Getenv(EnvWatchtowerTLSServerName); v != "" {
		foundTLSConfig = true
		envServerName = v
	}

	if v := os.Getenv(EnvWatchtowerSRVLookup); v != "" {
		var err error
		lookup, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("could not parse %s", EnvWatchtowerSRVLookup)
		}
		envSRVLookup = new(bool)
		*envSRVLookup = lookup
	}

	if v := os.Getenv(EnvWatchtowerRateLimit); v != "" {
		rateLimit, burstLimit, err := parseRateLimit(v)
		if err != nil {
			return err
		}
		limit = rate.NewLimiter(rate.Limit(rateLimit), burstLimit)
	}

	if t := os.Getenv(EnvWatchtowerClientTimeout); t != "" {
		clientTimeout, err := parseutil.ParseDurationSecond(t)
		if err != nil {
			return fmt.Errorf("could not parse %q", EnvWatchtowerClientTimeout)
		}
		envClientTimeout = clientTimeout
	}

	// Set the values on the config
	{
		if envToken != "" {
			c.Token = envToken
		}

		if envAddress != "" {
			c.Address = envAddress
		}

		if envMaxRetries != nil {
			c.MaxRetries = int(*envMaxRetries)
		}

		if envClientTimeout != 0 {
			c.Timeout = envClientTimeout
		}

		if envSRVLookup != nil {
			c.SRVLookup = *envSRVLookup
		}

		if limit != nil {
			c.Limiter = limit
		}

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
		}
	}

	if foundTLSConfig {
		return c.ConfigureTLS()
	}

	return nil
}

func parseRateLimit(val string) (rate float64, burst int, err error) {
	_, err = fmt.Sscanf(val, "%f:%d", &rate, &burst)
	if err != nil {
		rate, err = strconv.ParseFloat(val, 64)
		if err != nil {
			err = fmt.Errorf("%v was provided but incorrectly formatted", EnvWatchtowerRateLimit)
		}
		burst = int(rate)
	}

	return rate, burst, err
}

// Client is the client to the Vault API. Create a client with NewClient.
type Client struct {
	modifyLock sync.RWMutex
	config     *Config
}

// NewClient returns a new client for the given configuration.
//
// If the configuration is nil, Watchtower will use configuration from
// DefaultConfig(), which is the recommended starting configuration.
//
// If the environment variable `WATCHTOWER_TOKEN` is present, the token will be
// automatically added to the client. Otherwise, you must manually call
// `SetToken()`.
func NewClient(c *Config) (*Client, error) {
	def := DefaultConfig()
	if def == nil {
		return nil, fmt.Errorf("could not create/read default configuration")
	}
	if def.Error != nil {
		return nil, errwrap.Wrapf("error encountered setting up default configuration: {{err}}", def.Error)
	}

	if c == nil {
		c = def
	}

	if c.HTTPClient == nil {
		c.HTTPClient = def.HTTPClient
	}
	if c.HTTPClient.Transport == nil {
		c.HTTPClient.Transport = def.HTTPClient.Transport
	}
	if c.HTTPClient.CheckRedirect == nil {
		// Ensure redirects are not automatically followed
		c.HTTPClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			// Returning this value causes the Go net library to not close the
			// response body and to nil out the error. Otherwise retry clients may
			// try three times on every redirect because it sees an error from this
			// function (to prevent redirects) passing through to it.
			return http.ErrUseLastResponse
		}
	}

	return &Client{
		config: c,
	}, nil
}

// Sets the address of Watchtower in the client. The format of address should
// be "<Scheme>://<Host>:<Port>". Setting this on a client will override the
// value of the WATCHTOWER_ADDR environment variable.
func (c *Client) SetAddress(addr string) {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	c.config.Address = addr
}

// SetLimiter will set the rate limiter for this client.  This method is
// thread-safe.  rateLimit and burst are specified according to
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

// SetToken sets the token directly. This won't perform any auth
// verification, it simply sets the token properly for future requests.
func (c *Client) SetToken(token string) {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	c.config.Token = token
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
func (c *Client) Clone() (*Client, error) {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()

	config := c.config

	newConfig := &Config{
		Address:    config.Address,
		Token:      config.Token,
		HTTPClient: config.HTTPClient,
		Headers:    make(http.Header),
		MaxRetries: config.MaxRetries,
		Timeout:    config.Timeout,
		Backoff:    config.Backoff,
		CheckRetry: config.CheckRetry,
		Limiter:    config.Limiter,
		SRVLookup:  config.SRVLookup,
	}
	if config.TLSConfig != nil {
		newConfig.TLSConfig = new(TLSConfig)
		*newConfig.TLSConfig = *config.TLSConfig
	}
	for k, v := range config.Headers {
		vSlice := make([]string, 0, len(v))
		for _, i := range v {
			vSlice = append(vSlice, i)
		}
		newConfig.Headers[k] = vSlice
	}

	return NewClient(newConfig)
}

func copyHeaders(in http.Header) http.Header {
	ret := make(http.Header)
	for k, v := range in.headers {
		for _, val := range v {
			ret[k] = append(ret[k], val)
		}
	}

	return ret
}

// GetReaderFuncForJSON returns a func compatible with retryablehttp.ReaderFunc
// after marshaling JSON
func getBufferForJSON(val interface{}) (*bytes.Buffer, error) {
	b, err := json.Marshal(val)
	if err != nil {
		return nil, err
	}

	return bytes.NewBuffer(b), nil
}

// NewRequest creates a new raw request object to query the Watchtower controller
// configured for this client. This is an advanced method and generally
// doesn't need to be called externally.
func (c *Client) NewRequest(ctx context.Context, method, requestPath string, body interface{}) (*http.Request, error) {
	c.modifyLock.RLock()
	defer c.modifyLock.RUnlock()

	u, err := url.Parse(c.config.Address)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(c.config.Address, "unix://") {
		socket := strings.TrimPrefix(c.config.Address, "unix://")
		transport := c.config.HTTPClient.Transport.(*http.Transport)
		transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, "unix", socket)
		}

		// Since the address points to a unix domain socket, the scheme in the
		// *URL would be set to `unix`. The *URL in the client is expected to
		// be pointing to the protocol used in the application layer and not to
		// the transport layer. Hence, setting the fields accordingly.
		u.Scheme = "http"
		u.Host = socket
		u.Path = ""
	}

	var host = u.Host
	// if SRV records exist (see
	// https://tools.ietf.org/html/draft-andrews-http-srv-02), lookup the SRV
	// record and take the highest match; this is not designed for
	// high-availability, just discovery Internet Draft specifies that the SRV
	// record is ignored if a port is given
	if u.Port() == "" && c.config.SRVLookup {
		_, addrs, err := net.LookupSRV("http", "tcp", u.Hostname())
		if err != nil {
			return nil, fmt.Errorf("error performing SRV lookup of http:tcp:%s : %w", u.Hostname(), err)
		}
		if len(addrs) > 0 {
			host = fmt.Sprintf("%s:%d", addrs[0].Target, addrs[0].Port)
		}
	}

	req := &http.Request{
		Method: method,
		URL: &url.URL{
			User:   u.User,
			Scheme: u.Scheme,
			Host:   host,
			Path:   path.Join(u.Path, requestPath),
		},
		Host: u.Host,
	}
	req.Header = copyHeaders(c.config.Headers)
	req.Header.Add("authorization", "bearer: "+c.config.Token)
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// RawRequestWithContext performs the raw request given. This request may be against
// a Vault server not configured with this client. This is an advanced operation
// that generally won't need to be called externally.
func (c *Client) Do(r *http.Request) (*http.Response, error) {
	c.modifyLock.RLock()
	limiter := c.config.Limiter
	maxRetries := c.config.MaxRetries
	checkRetry := c.config.CheckRetry
	backoff := c.config.Backoff
	httpClient := c.config.HTTPClient
	timeout := c.config.Timeout
	token := c.config.Token
	outputCurlString := c.config.OutputCurlString
	c.modifyLock.RUnlock()

	ctx := r.Context()

	if limiter != nil {
		limiter.Wait(ctx)
	}

	// Sanity check the token before potentially erroring from the API
	idx := strings.IndexFunc(token, func(c rune) bool {
		return !unicode.IsPrint(c)
	})
	if idx != -1 {
		return nil, fmt.Errorf("configured Watchtower token contains non-printable characters and cannot be used")
	}

	req, err := retryablehttp.FromRequest(r)
	if err != nil {
		return nil, fmt.Errorf("error converting request to retryable request: %w", err)
	}
	if req == nil {
		return nil, fmt.Errorf("nil request created")
	}

	if outputCurlString {
		LastOutputStringError = &OutputStringError{Request: req}
		return nil, LastOutputStringError
	}

	if timeout != 0 {
		// NOTE: this leaks a timer. But when we defer a cancel call here for
		// the returned function we see errors in tests with contxt canceled.
		// Although the request is done by the time we exit this function it is
		// still causing something else to go wrong. Maybe it ends up being
		// tied to the response somehow and reading the response body ends up
		// checking it, or something. I don't know, but until we can chase this
		// down, keep it not-canceled even though vet complains.
		ctx, _ = context.WithTimeout(ctx, timeout)
	}
	req.Request = req.Request.WithContext(ctx)

	if backoff == nil {
		backoff = retryablehttp.LinearJitterBackoff
	}

	if checkRetry == nil {
		checkRetry = retryablehttp.DefaultRetryPolicy
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

	var result *http.Response
	resp, err := client.Do(req)
	if resp != nil {
		result = &Response{Response: resp}
	}
	if err != nil {
		if strings.Contains(err.Error(), "tls: oversized") {
			err = errwrap.Wrapf(
				"{{err}}\n\n"+
					"This error usually means that the controller is running with TLS disabled\n"+
					"but the client is configured to use TLS. Please either enable TLS\n"+
					"on the server or run the client with -address set to an address\n"+
					"that uses the http protocol:\n\n"+
					"    watchtower <command> -address http://<address>\n\n"+
					"You can also set the WATCHTOWER_ADDR environment variable:\n\n\n"+
					"    WATCHTOWER_ADDR=http://<address> watchtower <command>\n\n"+
					"where <address> is replaced by the actual address to the controller.",
				err)
		}
		return result, err
	}

	return result, nil
}
