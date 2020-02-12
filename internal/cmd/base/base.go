package base

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"regexp"
	"strings"
	"sync"

	"github.com/mitchellh/cli"
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

type BaseCommand struct {
	UI      cli.Ui
	Address string
	Context context.Context

	flags     *FlagSets
	flagsOnce sync.Once

	flagCACert        string
	flagCAPath        string
	flagClientCert    string
	flagClientKey     string
	flagTLSServerName string
	flagTLSInsecure   bool

	flagFormat           string
	flagField            string
	flagOutputCurlString bool
}

func (c *BaseCommand) SetAddress(addr string) {
	c.Address = addr
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
func (c *BaseCommand) FlagSet(bit FlagSetBit) *FlagSets {
	c.flagsOnce.Do(func() {
		set := NewFlagSets(c.UI)

		// These flag sets will apply to all leaf subcommands.
		// TODO: Optional, but FlagSetHTTP can be safely removed from the individual
		// Flags() subcommands.
		bit = bit | FlagSetHTTP

		if bit&FlagSetHTTP != 0 {
			f := set.NewFlagSet("HTTP Options")

			addrStringVar := &StringVar{
				Name:       FlagNameAddress,
				Target:     &c.Address,
				EnvVar:     EnvWatchtowerAddress,
				Completion: complete.PredictAnything,
				Usage:      "Address of the Watchtower controller.",
			}
			if c.Address != "" {
				addrStringVar.Default = c.Address
			} else {
				addrStringVar.Default = "https://127.0.0.1:9200"
			}
			f.StringVar(addrStringVar)

			f.StringVar(&StringVar{
				Name:       FlagNameCACert,
				Target:     &c.flagCACert,
				Default:    "",
				EnvVar:     EnvWatchtowerCACert,
				Completion: complete.PredictFiles("*"),
				Usage: "Path on the local disk to a single PEM-encoded CA " +
					"certificate to verify the Controller or Worker's server's SSL certificate. This " +
					"takes precedence over -ca-path.",
			})

			f.StringVar(&StringVar{
				Name:       FlagNameCAPath,
				Target:     &c.flagCAPath,
				Default:    "",
				EnvVar:     EnvWatchtowerCAPath,
				Completion: complete.PredictDirs("*"),
				Usage: "Path on the local disk to a directory of PEM-encoded CA " +
					"certificates to verify the SSL certificate of the Controller.",
			})

			f.StringVar(&StringVar{
				Name:       FlagNameClientCert,
				Target:     &c.flagClientCert,
				Default:    "",
				EnvVar:     EnvWatchtowerClientCert,
				Completion: complete.PredictFiles("*"),
				Usage: "Path on the local disk to a single PEM-encoded CA " +
					"certificate to use for TLS authentication to the Watchtower Controller. If " +
					"this flag is specified, -client-key is also required.",
			})

			f.StringVar(&StringVar{
				Name:       FlagNameClientKey,
				Target:     &c.flagClientKey,
				Default:    "",
				EnvVar:     EnvWatchtowerClientKey,
				Completion: complete.PredictFiles("*"),
				Usage: "Path on the local disk to a single PEM-encoded private key " +
					"matching the client certificate from -client-cert.",
			})

			f.StringVar(&StringVar{
				Name:       FlagTLSServerName,
				Target:     &c.flagTLSServerName,
				Default:    "",
				EnvVar:     EnvWatchtowerTLSServerName,
				Completion: complete.PredictAnything,
				Usage: "Name to use as the SNI host when connecting to the Watchtower " +
					"server via TLS.",
			})

			f.BoolVar(&BoolVar{
				Name:    FlagNameTLSInsecure,
				Target:  &c.flagTLSInsecure,
				Default: false,
				EnvVar:  EnvWatchtowerTLSInsecure,
				Usage: "Disable verification of TLS certificates. Using this option " +
					"is highly discouraged as it decreases the security of data " +
					"transmissions to and from the Watchtower server.",
			})

			f.BoolVar(&BoolVar{
				Name:    "output-curl-string",
				Target:  &c.flagOutputCurlString,
				Default: false,
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
