package base

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/hashicorp/watchtower/api"
	"github.com/mitchellh/cli"
	"github.com/pkg/errors"
	"github.com/posener/complete"
)

const (
	// maxLineLength is the maximum width of any line.
	maxLineLength int = 78

	// NotSetValue is a flag value for a not-set value
	NotSetValue = "(not set)"
)

// reRemoveWhitespace is a regular expression for stripping whitespace from
// a string.
var reRemoveWhitespace = regexp.MustCompile(`[\s]+`)

type Command struct {
	Context    context.Context
	UI         cli.Ui
	ShutdownCh chan struct{}

	flags     *FlagSets
	flagsOnce sync.Once

	flagAddr    string
	flagOrg     string
	flagProject string

	flagTLSCACert     string
	flagTLSCAPath     string
	flagTLSClientCert string
	flagTLSClientKey  string
	flagTLSServerName string
	flagTLSInsecure   bool

	flagFormat           string
	flagField            string
	flagOutputCurlString bool

	client *api.Client
}

// New returns a new instance of a base.Command type
func New(ui cli.Ui) *Command {
	ctx, cancel := context.WithCancel(context.Background())
	ret := &Command{
		UI:         ui,
		ShutdownCh: MakeShutdownCh(),
		Context:    ctx,
	}

	go func() {
		<-ret.ShutdownCh
		cancel()
	}()

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
		<-shutdownCh
		close(resultCh)
	}()
	return resultCh
}

// Client returns the HTTP API client. The client is cached on the command to
// save performance on future calls.
func (c *Command) Client() (*api.Client, error) {
	// Read the test client if present
	if c.client != nil {
		return c.client, nil
	}

	config, err := api.DefaultConfig()
	if err != nil {
		return nil, err
	}

	if c.flagOutputCurlString {
		config.OutputCurlString = c.flagOutputCurlString
	}

	c.client, err = api.NewClient(config)
	if err != nil {
		return nil, err
	}

	if c.flagAddr != NotSetValue {
		c.client.SetAddr(c.flagAddr)
	}
	if c.flagOrg != NotSetValue {
		c.client.SetOrg(c.flagOrg)
	}
	if c.flagProject != NotSetValue {
		c.client.SetProject(c.flagProject)
	}

	// If we need custom TLS configuration, then set it
	var modifiedTLS bool
	tlsConfig := config.TLSConfig
	if c.flagTLSCACert != NotSetValue {
		tlsConfig.CACert = c.flagTLSCACert
		modifiedTLS = true
	}
	if c.flagTLSCAPath != NotSetValue {
		tlsConfig.CAPath = c.flagTLSCAPath
		modifiedTLS = true
	}
	if c.flagTLSClientCert != NotSetValue {
		tlsConfig.ClientCert = c.flagTLSClientCert
		modifiedTLS = true
	}
	if c.flagTLSClientKey != NotSetValue {
		tlsConfig.ClientKey = c.flagTLSClientKey
		modifiedTLS = true
	}
	if c.flagTLSServerName != NotSetValue {
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
			return nil, errors.Wrap(err, "failed to setup TLS config")
		}
	}

	// Turn off retries on the CLI
	if os.Getenv(api.EnvWatchtowerMaxRetries) == "" {
		c.client.SetMaxRetries(0)
	}

	return c.client, nil
}

type FlagSetBit uint

const (
	FlagSetNone FlagSetBit = 1 << iota
	FlagSetHTTP
	FlagSetOutputField
	FlagSetOutputFormat
)

// FlagSet creates the flags for this command. The result is cached on the
// command to save performance on future calls.
func (c *Command) FlagSet(bit FlagSetBit) *FlagSets {
	c.flagsOnce.Do(func() {
		set := NewFlagSets(c.UI)

		// These flag sets will apply to all leaf subcommands.
		// TODO: Optional, but FlagSetHTTP can be safely removed from the individual
		// Flags() subcommands.
		bit = bit | FlagSetHTTP

		if bit&FlagSetHTTP != 0 {
			f := set.NewFlagSet("Connection Options")

			f.StringVar(&StringVar{
				Name:       FlagNameAddr,
				Target:     &c.flagAddr,
				Default:    NotSetValue,
				EnvVar:     api.EnvWatchtowerAddr,
				Completion: complete.PredictAnything,
				Usage:      "Addr of the Watchtower controller, as a complete URL (e.g. https://watchtower.example.com:9200).",
			})

			f.StringVar(&StringVar{
				Name:       FlagNameOrg,
				Target:     &c.flagOrg,
				Default:    NotSetValue,
				EnvVar:     api.EnvWatchtowerOrg,
				Completion: complete.PredictAnything,
				Usage:      "Organization in which to make the request; overrides any set in the address.",
			})

			f.StringVar(&StringVar{
				Name:       FlagNameProject,
				Target:     &c.flagProject,
				Default:    NotSetValue,
				EnvVar:     api.EnvWatchtowerProject,
				Completion: complete.PredictAnything,
				Usage:      "Project in which to make the request; overrides any set in the address.",
			})

			f.StringVar(&StringVar{
				Name:       FlagNameCACert,
				Target:     &c.flagTLSCACert,
				Default:    NotSetValue,
				EnvVar:     api.EnvWatchtowerCACert,
				Completion: complete.PredictFiles("*"),
				Usage: "Path on the local disk to a single PEM-encoded CA " +
					"certificate to verify the Controller or Worker's server's SSL certificate. This " +
					"takes precedence over -ca-path.",
			})

			f.StringVar(&StringVar{
				Name:       FlagNameCAPath,
				Target:     &c.flagTLSCAPath,
				Default:    NotSetValue,
				EnvVar:     api.EnvWatchtowerCAPath,
				Completion: complete.PredictDirs("*"),
				Usage: "Path on the local disk to a directory of PEM-encoded CA " +
					"certificates to verify the SSL certificate of the Controller.",
			})

			f.StringVar(&StringVar{
				Name:       FlagNameClientCert,
				Target:     &c.flagTLSClientCert,
				Default:    NotSetValue,
				EnvVar:     api.EnvWatchtowerClientCert,
				Completion: complete.PredictFiles("*"),
				Usage: "Path on the local disk to a single PEM-encoded CA " +
					"certificate to use for TLS authentication to the Watchtower Controller. If " +
					"this flag is specified, -client-key is also required.",
			})

			f.StringVar(&StringVar{
				Name:       FlagNameClientKey,
				Target:     &c.flagTLSClientKey,
				Default:    NotSetValue,
				EnvVar:     api.EnvWatchtowerClientKey,
				Completion: complete.PredictFiles("*"),
				Usage: "Path on the local disk to a single PEM-encoded private key " +
					"matching the client certificate from -client-cert.",
			})

			f.StringVar(&StringVar{
				Name:       FlagTLSServerName,
				Target:     &c.flagTLSServerName,
				Default:    NotSetValue,
				EnvVar:     api.EnvWatchtowerTLSServerName,
				Completion: complete.PredictAnything,
				Usage: "Name to use as the SNI host when connecting to the Watchtower " +
					"server via TLS.",
			})

			f.BoolVar(&BoolVar{
				Name:   FlagNameTLSInsecure,
				Target: &c.flagTLSInsecure,
				EnvVar: api.EnvWatchtowerTLSInsecure,
				Usage: "Disable verification of TLS certificates. Using this option " +
					"is highly discouraged as it decreases the security of data " +
					"transmissions to and from the Watchtower server.",
			})

			f.BoolVar(&BoolVar{
				Name:   "output-curl-string",
				Target: &c.flagOutputCurlString,
				Usage: "Instead of executing the request, print an equivalent cURL " +
					"command string and exit.",
			})
		}

		if bit&(FlagSetOutputField|FlagSetOutputFormat) != 0 {
			f := set.NewFlagSet("Output Options")

			if bit&FlagSetOutputField != 0 {
				f.StringVar(&StringVar{
					Name:       "field",
					Target:     &c.flagField,
					Default:    "",
					Completion: complete.PredictAnything,
					Usage: "Print only the field with the given name. Specifying " +
						"this option will take precedence over other formatting " +
						"directives. The result will not have a trailing newline " +
						"making it ideal for piping to other processes.",
				})
			}

			if bit&FlagSetOutputFormat != 0 {
				f.StringVar(&StringVar{
					Name:       "format",
					Target:     &c.flagFormat,
					Default:    "table",
					EnvVar:     EnvWatchtowerCLIFormat,
					Completion: complete.PredictSet("table", "json", "yaml"),
					Usage: "Print the output in the given format. Valid formats " +
						"are \"table\", \"json\", or \"yaml\".",
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
	mainSet.SetOutput(ioutil.Discard)

	return &FlagSets{
		flagSets:    make([]*FlagSet, 0, 6),
		mainSet:     mainSet,
		hiddens:     make(map[string]struct{}),
		completions: complete.Flags{},
	}
}

// NewFlagSet creates a new flag set from the given flag sets.
func (f *FlagSets) NewFlagSet(name string) *FlagSet {
	flagSet := NewFlagSet(name)
	flagSet.mainSet = f.mainSet
	flagSet.completions = f.completions
	f.flagSets = append(f.flagSets, flagSet)
	return flagSet
}

// Completions returns the completions for this flag set.
func (f *FlagSets) Completions() complete.Flags {
	return f.completions
}

// Parse parses the given flags, returning any errors.
func (f *FlagSets) Parse(args []string) error {
	return f.mainSet.Parse(args)
}

// Parsed reports whether the command-line flags have been parsed.
func (f *FlagSets) Parsed() bool {
	return f.mainSet.Parsed()
}

// Args returns the remaining args after parsing.
func (f *FlagSets) Args() []string {
	return f.mainSet.Args()
}

// Visit visits the flags in lexicographical order, calling fn for each. It
// visits only those flags that have been set.
func (f *FlagSets) Visit(fn func(*flag.Flag)) {
	f.mainSet.Visit(fn)
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
