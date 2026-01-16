// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/globals"
	kms_plugin_assets "github.com/hashicorp/boundary/plugins/kms"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	configutil "github.com/hashicorp/go-secure-stdlib/configutil/v2"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/pluginutil/v2"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

type EnabledPlugin uint

const (
	EnabledPluginUnknown EnabledPlugin = iota
	EnabledPluginLoopback
	EnabledPluginAws
	EnabledPluginHostAzure
	EnabledPluginMinio
	EnabledPluginGCP
)

// MinioEnabled controls if the Minio storage plugin should be initiated or not
var MinioEnabled bool

func (e EnabledPlugin) String() string {
	switch e {
	case EnabledPluginLoopback:
		return "Loopback"
	case EnabledPluginAws:
		return "AWS"
	case EnabledPluginHostAzure:
		return "Azure"
	case EnabledPluginMinio:
		return "MinIO"
	case EnabledPluginGCP:
		return "GCP"
	default:
		return ""
	}
}

const (
	CommandSuccess int = iota
	CommandApiError
	CommandCliError
	CommandUserError
)

const (
	// maxLineLength is the maximum width of any line.
	maxLineLength int = 78

	envToken                             = "BOUNDARY_TOKEN"
	EnvTokenName                         = "BOUNDARY_TOKEN_NAME"
	EnvKeyringType                       = "BOUNDARY_KEYRING_TYPE"
	envRecoveryConfig                    = "BOUNDARY_RECOVERY_CONFIG"
	envSkipCacheDaemon                   = "BOUNDARY_SKIP_CACHE_DAEMON"
	envSkipClientAgent                   = "BOUNDARY_SKIP_CLIENT_AGENT"
	EnvClientAgentPort                   = "BOUNDARY_CLIENT_AGENT_LISTENING_PORT"
	EnvBoundaryClientAgentCliErrorOutput = "BOUNDARY_CLIENT_AGENT_CLI_ERROR_OUTPUT"

	StoredTokenName = "HashiCorp Boundary Auth Token"
)

// reRemoveWhitespace is a regular expression for stripping whitespace from
// a string.
var reRemoveWhitespace = regexp.MustCompile(`[\s]+`)

var DevOnlyControllerFlags = func(*Command, *FlagSet) {}

type Command struct {
	Context       context.Context
	ContextCancel context.CancelFunc
	UI            cli.Ui
	ShutdownCh    chan struct{}

	Opts []Option

	flags     *FlagSets
	flagsOnce sync.Once

	FlagAddr    string
	flagVerbose bool

	flagTLSCACert     string
	flagTLSCAPath     string
	flagTLSClientCert string
	flagTLSClientKey  string
	flagTLSServerName string
	flagTLSInsecure   bool

	flagFormat                    string
	FlagToken                     string
	FlagTokenName                 string
	FlagKeyringType               string
	FlagRecoveryConfig            string
	FlagOutputCurlString          bool
	FlagSkipCacheDaemon           bool
	FlagSkipClientAgent           bool
	FlagOutputClientAgentCliError bool

	FlagClientAgentPort uint16

	FlagScopeId           string
	FlagScopeName         string
	FlagPluginId          string
	FlagPluginName        string
	FlagId                string
	FlagName              string
	FlagDescription       string
	FlagAuthMethodId      string
	FlagHostCatalogId     string
	FlagCredentialStoreId string
	FlagVersion           int64
	FlagRecursive         bool
	FlagFilter            string
	FlagTags              map[string][]string
	FlagOutputFile        string // the output file for the command
	FlagNoClobber         bool   // Don't clobber the output file

	// Attribute values
	FlagAttributes string
	FlagAttrs      []CombinedSliceFlagValue

	// Secret values
	FlagSecrets string
	FlagScrts   []CombinedSliceFlagValue

	// Object values
	FlagObject string
	FlagKv     []CombinedSliceFlagValue

	client *api.Client

	// This will be intialized, if needed, in Config() when instantiating a
	// recovery wrapper, if requested. It's then called as a deferred function
	// on the Run method of the various generated commands.
	WrapperCleanupFunc func() error
}

// New returns a new instance of a base.Command type
func NewCommand(ui cli.Ui, opt ...Option) *Command {
	opts := GetOpts(opt...)
	ctx, cancel := context.WithCancel(context.Background())
	ret := &Command{
		UI:         ui,
		ShutdownCh: MakeShutdownCh(),
		Context:    ctx,
		FlagId:     opts.withImplicitId,
	}
	go func() {
		<-ret.ShutdownCh
		cancel()
	}()

	return ret
}

// New returns a new instance of a base.Command type that does not intercept the shutdown channel
func NewServerCommand(ui cli.Ui) *Command {
	ctx, cancel := context.WithCancel(context.Background())
	ret := &Command{
		UI:            ui,
		ShutdownCh:    MakeShutdownCh(),
		Context:       ctx,
		ContextCancel: cancel,
	}

	return ret
}

// MakeShutdownCh returns a channel that can be used for shutdown
// notifications for commands. This channel will send a message for every
// SIGINT or SIGTERM received.
func MakeShutdownCh() chan struct{} {
	resultCh := make(chan struct{})

	shutdownCh := make(chan os.Signal, 4)
	signal.Notify(shutdownCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		for {
			<-shutdownCh
			resultCh <- struct{}{}
		}
	}()
	return resultCh
}

func (c *Command) BaseCommand() *Command {
	return c
}

// Client returns the HTTP API client. The client is cached on the command to
// save performance on future calls.
func (c *Command) Client(opt ...Option) (*api.Client, error) {
	// Read the cached client if present
	if c.client != nil {
		return c.client, nil
	}

	opts := GetOpts(opt...)

	config, err := api.DefaultConfig()
	if err != nil {
		return nil, err
	}

	if c.FlagOutputCurlString {
		config.OutputCurlString = c.FlagOutputCurlString
	}

	c.client, err = api.NewClient(config)
	if err != nil {
		return nil, err
	}
	if c.FlagAddr != "" {
		if err := c.client.SetAddr(c.FlagAddr); err != nil {
			return nil, fmt.Errorf("error setting address on client: %w", err)
		}
	}

	// If we need custom TLS configuration, then set it
	var modifiedTLS bool
	tlsConfig := config.TLSConfig
	if c.flagTLSCACert != "" {
		tlsConfig.CACert = c.flagTLSCACert
		modifiedTLS = true
	}
	if c.flagTLSCAPath != "" {
		tlsConfig.CAPath = c.flagTLSCAPath
		modifiedTLS = true
	}
	if c.flagTLSClientCert != "" {
		tlsConfig.ClientCert = c.flagTLSClientCert
		modifiedTLS = true
	}
	if c.flagTLSClientKey != "" {
		tlsConfig.ClientKey = c.flagTLSClientKey
		modifiedTLS = true
	}
	if c.flagTLSServerName != "" {
		tlsConfig.ServerName = c.flagTLSServerName
		modifiedTLS = true
	}
	if c.flagTLSInsecure {
		tlsConfig.Insecure = c.flagTLSInsecure
		modifiedTLS = true
	}
	if modifiedTLS {
		// Setup TLS config
		if err := c.client.SetTLSConfig(tlsConfig); err != nil {
			return nil, fmt.Errorf("failed to setup TLS config: %w", err)
		}
	}

	// Turn off retries on the CLI
	if os.Getenv(api.EnvBoundaryMaxRetries) == "" {
		c.client.SetMaxRetries(0)
	}

	switch {
	case opts.withNoTokenValue:
		c.client.SetToken("")

	case c.FlagRecoveryConfig != "":
		wrapper, cleanupFunc, err := wrapper.GetWrapperFromPath(
			c.Context,
			c.FlagRecoveryConfig,
			globals.KmsPurposeRecovery,
			configutil.WithPluginOptions(
				pluginutil.WithPluginsMap(kms_plugin_assets.BuiltinKmsPlugins()),
				pluginutil.WithPluginsFilesystem(kms_plugin_assets.KmsPluginPrefix, kms_plugin_assets.FileSystem()),
			),
			// TODO: How would we want to expose this kind of log to users when
			// using recovery configs? Generally with normal CLI commands we
			// don't print out all of these logs. We may want a logger with a
			// custom writer behind our existing gate where we print nothing
			// unless there is an error, then dump all of it.
			configutil.WithLogger(hclog.NewNullLogger()),
		)
		if err != nil {
			return nil, err
		}
		if wrapper == nil {
			return nil, errors.New(`No "kms" block with purpose "recovery" found`)
		}
		if cleanupFunc != nil {
			c.WrapperCleanupFunc = cleanupFunc
		}
		if ifWrapper, ok := wrapper.(wrapping.InitFinalizer); ok {
			if err := ifWrapper.Init(c.Context); err != nil && !errors.Is(err, wrapping.ErrFunctionNotImplemented) {
				return nil, fmt.Errorf("Error initializing kms: %w", err)
			}

			currCleanupFunc := c.WrapperCleanupFunc
			c.WrapperCleanupFunc = func() error {
				if err := ifWrapper.Finalize(context.Background()); err != nil && !errors.Is(err, wrapping.ErrFunctionNotImplemented) {
					c.PrintCliError(fmt.Errorf("An error was encountered finalizing the kms: %w", err))
				}
				if currCleanupFunc != nil {
					return currCleanupFunc()
				}
				return nil
			}
		}

		c.client.SetRecoveryKmsWrapper(wrapper)

	case c.FlagToken != "":
		token, err := parseutil.MustParsePath(c.FlagToken)
		switch {
		case err == nil:
		case errors.Is(err, parseutil.ErrNotParsed):
			return nil, errors.New("Token flag must be used with env:// or file:// syntax")
		default:
			return nil, fmt.Errorf("error parsing token flag: %w", err)
		}
		c.client.SetToken(token)

	case os.Getenv(envToken) != "":
		// Backwards compat: allow reading from existing BOUNDARY_TOKEN env var
		c.UI.Warn(`Direct usage of BOUNDARY_TOKEN env var is deprecated; please use "-token env://<env var name>" format, e.g. "-token env://BOUNDARY_TOKEN" to specify an env var to use.`)
		c.client.SetToken(os.Getenv(envToken))

	case c.client.Token() == "" && strings.ToLower(c.FlagKeyringType) != "none":
		keyringType, tokenName, err := c.DiscoverKeyringTokenInfo()
		if err != nil {
			return nil, err
		}

		authToken, err := c.ReadTokenFromKeyring(keyringType, tokenName)
		if err != nil {
			c.UI.Error(err.Error())
		} else {
			c.client.SetToken(authToken.Token)
		}
	}

	return c.client, nil
}

// If the first arg isn't a flag, extract it as the alias and return the remaining args
func ExtractAliasFromArgs(inArgs []string) (string, []string) {
	if len(inArgs) > 0 && inArgs[0][0] != '-' {
		return inArgs[0], inArgs[1:]
	}

	return "", inArgs
}

type FlagSetBit uint

const (
	FlagSetNone FlagSetBit = 1 << iota
	FlagSetHTTP
	FlagSetClient
	FlagSetOutputFormat
)

// FlagSet creates the flags for this command. The result is cached on the
// command to save performance on future calls.
func (c *Command) FlagSet(bit FlagSetBit) *FlagSets {
	c.flagsOnce.Do(func() {
		set := NewFlagSets(c.UI)

		if bit&FlagSetHTTP != 0 {
			f := set.NewFlagSet("Connection Options")

			f.StringVar(&StringVar{
				Name:       FlagNameAddr,
				Target:     &c.FlagAddr,
				EnvVar:     api.EnvBoundaryAddr,
				Completion: complete.PredictAnything,
				Usage:      "Addr of the Boundary controller, as a complete URL (e.g. https://boundary.example.com:9200).",
			})

			f.StringVar(&StringVar{
				Name:       FlagNameCACert,
				Target:     &c.flagTLSCACert,
				EnvVar:     api.EnvBoundaryCACert,
				Completion: complete.PredictFiles("*"),
				Usage: "Path on the local disk to a single PEM-encoded CA " +
					"certificate to verify the Controller or Worker's server's SSL certificate. This " +
					"takes precedence over -ca-path.",
			})

			f.StringVar(&StringVar{
				Name:       FlagNameCAPath,
				Target:     &c.flagTLSCAPath,
				EnvVar:     api.EnvBoundaryCAPath,
				Completion: complete.PredictDirs("*"),
				Usage: "Path on the local disk to a directory of PEM-encoded CA " +
					"certificates to verify the SSL certificate of the Controller.",
			})

			f.StringVar(&StringVar{
				Name:       FlagNameClientCert,
				Target:     &c.flagTLSClientCert,
				EnvVar:     api.EnvBoundaryClientCert,
				Completion: complete.PredictFiles("*"),
				Usage: "Path on the local disk to a single PEM-encoded CA " +
					"certificate to use for TLS authentication to the Boundary Controller. If " +
					"this flag is specified, -client-key is also required.",
			})

			f.StringVar(&StringVar{
				Name:       FlagNameClientKey,
				Target:     &c.flagTLSClientKey,
				EnvVar:     api.EnvBoundaryClientKey,
				Completion: complete.PredictFiles("*"),
				Usage: "Path on the local disk to a single PEM-encoded private key " +
					"matching the client certificate from -client-cert.",
			})

			f.StringVar(&StringVar{
				Name:       FlagTLSServerName,
				Target:     &c.flagTLSServerName,
				EnvVar:     api.EnvBoundaryTLSServerName,
				Completion: complete.PredictAnything,
				Usage: "Name to use as the SNI host when connecting to the Boundary " +
					"server via TLS.",
			})

			f.BoolVar(&BoolVar{
				Name:   FlagNameTLSInsecure,
				Target: &c.flagTLSInsecure,
				EnvVar: api.EnvBoundaryTLSInsecure,
				Usage: "Disable verification of TLS certificates. Using this option " +
					"is highly discouraged as it decreases the security of data " +
					"transmissions to and from the Boundary server.",
			})
		}

		if bit&FlagSetClient != 0 {
			f := set.NewFlagSet("Client Options")

			f.StringVar(&StringVar{
				Name:   "token-name",
				Target: &c.FlagTokenName,
				EnvVar: EnvTokenName,
				Usage:  `If specified, the given value will be used as the name when storing the token in the system credential store. This can allow switching user identities for different commands.`,
			})

			f.StringVar(&StringVar{
				Name:    "keyring-type",
				Target:  &c.FlagKeyringType,
				Default: "auto",
				EnvVar:  EnvKeyringType,
				Usage:   `The type of keyring to use. Defaults to "auto" which will use the Windows credential manager, OSX keychain, or cross-platform password store depending on platform. Set to "none" to disable keyring functionality. Available types, depending on platform, are: "wincred", "keychain", "pass", and "secret-service".`,
			})

			f.StringVar(&StringVar{
				Name:   "token",
				Target: &c.FlagToken,
				Usage:  `A URL pointing to a file on disk (file://) from which a token will be read or an env var (env://) from which the token will be read. Overrides the "token-name" parameter.`,
			})

			f.StringVar(&StringVar{
				Name:   "recovery-config",
				Target: &c.FlagRecoveryConfig,
				EnvVar: envRecoveryConfig,
				Usage:  `If specified, the given config file will be parsed for a "kms" block with purpose "recovery" and will use the recovery mechanism to authorize the call."`,
			})

			f.BoolVar(&BoolVar{
				Name:   "output-curl-string",
				Target: &c.FlagOutputCurlString,
				Usage:  "Instead of executing the request, print an equivalent cURL command string and exit.",
			})

			f.BoolVar(&BoolVar{
				Name:    "skip-cache-daemon",
				Target:  &c.FlagSkipCacheDaemon,
				Default: false,
				EnvVar:  envSkipCacheDaemon,
				Usage:   "Skips starting the caching daemon or sending the current used/retrieved token to the caching daemon.",
			})

			f.BoolVar(&BoolVar{
				Name:    "output-client-agent-cli-error",
				Target:  &c.FlagOutputClientAgentCliError,
				Default: false,
				EnvVar:  EnvBoundaryClientAgentCliErrorOutput,
				Usage:   "Enables outputting CLI errors encountered for client-agent callbacks.",
			})

			f.BoolVar(&BoolVar{
				Name:    "skip-client-agent",
				Target:  &c.FlagSkipClientAgent,
				Default: false,
				EnvVar:  envSkipClientAgent,
				Usage:   "Skips sending the auth token used for this command to the client agent if it is running.",
				Hidden:  true,
			})

			f.Uint16Var(&Uint16Var{
				Name:    "client-agent-port",
				Target:  &c.FlagClientAgentPort,
				Default: 9300,
				EnvVar:  EnvClientAgentPort,
				Usage:   "The port on which the client agent is listening.",
				Hidden:  true,
			})
		}

		if bit&FlagSetOutputFormat != 0 {
			f := set.NewFlagSet("Output Options")

			/*
				f.BoolVar(&BoolVar{
					Name:       "verbose",
					Target:     &c.flagVerbose,
					Completion: complete.PredictAnything,
					Usage:      "Turns on some extra verbosity in the command output.",
				})
			*/

			if bit&FlagSetOutputFormat != 0 {
				f.StringVar(&StringVar{
					Name:       "format",
					Target:     &c.flagFormat,
					Default:    "table",
					EnvVar:     EnvBoundaryCLIFormat,
					Completion: complete.PredictSet("table", "json", "yaml"),
					Usage:      "Print the output in the given format. Valid formats are \"table\" or \"json\".",
				})
			}
		}

		c.flags = set
	})

	return c.flags
}

// FlagSets is a group of flag sets.
type FlagSets struct {
	flagSets    []*FlagSet
	mainSet     *flag.FlagSet
	hiddens     map[string]struct{}
	completions complete.Flags
}

// NewFlagSets creates a new flag sets.
func NewFlagSets(ui cli.Ui) *FlagSets {
	mainSet := flag.NewFlagSet("", flag.ContinueOnError)

	// Errors and usage are controlled by the CLI.
	mainSet.Usage = func() {}
	mainSet.SetOutput(io.Discard)

	return &FlagSets{
		flagSets:    make([]*FlagSet, 0, 6),
		mainSet:     mainSet,
		hiddens:     make(map[string]struct{}),
		completions: complete.Flags{},
	}
}

// NewFlagSet creates a new flag set from the given flag sets.
func (fs *FlagSets) NewFlagSet(name string) *FlagSet {
	flagSet := NewFlagSet(name)
	flagSet.mainSet = fs.mainSet
	flagSet.completions = fs.completions
	fs.flagSets = append(fs.flagSets, flagSet)
	return flagSet
}

// Completions returns the completions for this flag set.
func (fs *FlagSets) Completions() complete.Flags {
	if fs == nil {
		return nil
	}
	return fs.completions
}

// Parse parses the given flags, returning any errors.
func (fs *FlagSets) Parse(args []string) error {
	return fs.mainSet.Parse(args)
}

// Parsed reports whether the command-line flags have been parsed.
func (fs *FlagSets) Parsed() bool {
	return fs.mainSet.Parsed()
}

// Args returns the remaining args after parsing.
func (fs *FlagSets) Args() []string {
	return fs.mainSet.Args()
}

// Visit visits the flags in lexicographical order, calling fn for each. It
// visits only those flags that have been set.
func (fs *FlagSets) Visit(fn func(*flag.Flag)) {
	fs.mainSet.Visit(fn)
}

// Help builds custom help for this command, grouping by flag set.
func (fs *FlagSets) Help() string {
	var out bytes.Buffer

	for _, set := range fs.flagSets {
		printFlagTitle(&out, set.name+":")
		set.VisitAll(func(f *flag.Flag) {
			// Skip any hidden flags
			if v, ok := f.Value.(FlagVisibility); ok && v.Hidden() {
				return
			}
			printFlagDetail(&out, f)
		})
	}

	return strings.TrimRight(out.String(), "\n")
}

// FlagSet is a grouped wrapper around a real flag set and a grouped flag set.
type FlagSet struct {
	name        string
	flagSet     *flag.FlagSet
	mainSet     *flag.FlagSet
	completions complete.Flags
}

// NewFlagSet creates a new flag set.
func NewFlagSet(name string) *FlagSet {
	return &FlagSet{
		name:    name,
		flagSet: flag.NewFlagSet(name, flag.ContinueOnError),
	}
}

// Name returns the name of this flag set.
func (f *FlagSet) Name() string {
	return f.name
}

func (f *FlagSet) Visit(fn func(*flag.Flag)) {
	f.flagSet.Visit(fn)
}

func (f *FlagSet) VisitAll(fn func(*flag.Flag)) {
	f.flagSet.VisitAll(fn)
}

// printFlagTitle prints a consistently-formatted title to the given writer.
func printFlagTitle(w io.Writer, s string) {
	fmt.Fprintf(w, "%s\n\n", s)
}

// printFlagDetail prints a single flag to the given writer.
func printFlagDetail(w io.Writer, f *flag.Flag) {
	// Check if the flag is hidden - do not print any flag detail or help output
	// if it is hidden.
	if h, ok := f.Value.(FlagVisibility); ok && h.Hidden() {
		return
	}

	// Check for a detailed example
	example := ""
	if t, ok := f.Value.(FlagExample); ok {
		example = t.Example()
	}

	if example != "" {
		fmt.Fprintf(w, "  -%s=<%s>\n", f.Name, example)
	} else {
		fmt.Fprintf(w, "  -%s\n", f.Name)
	}

	usage := reRemoveWhitespace.ReplaceAllString(f.Usage, " ")
	indented := WrapAtLengthWithPadding(usage, 6)
	fmt.Fprintf(w, "%s\n\n", indented)
}
