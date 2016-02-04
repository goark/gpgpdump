package facade

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/spiegel-im-spiegel/gocli"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse"
)

// Exit Status
const (
	ExitSuccess = iota
	ExitFailure
)

// Errors
var (
	ErrFacadeTest = errors.New("facade test")
)

// Facade of facade context
type Facade struct {
	//UI is Command line user interface
	*gocli.UI
	// Name of application
	Name string
	//Version of application
	Version string
	//command for parsing
	command *parse.Context
}

// NewFacade returns a new Facade instance
func NewFacade(appName, version string, ui *gocli.UI) *Facade {
	return &Facade{UI: ui, Name: appName, Version: version}
}

// Run Application
func (f *Facade) Run(args []string) (int, error) {
	f.command = parse.Command(f.UI)

	flags := flag.NewFlagSet(f.Name, flag.ContinueOnError)
	flags.BoolVar(&f.command.Hflag, "h", false, "output this help")
	flags.BoolVar(&f.command.Vflag, "v", false, "output version")
	flags.BoolVar(&f.command.Aflag, "a", false, "accepts ASCII input only")
	//flags.BoolVar(&f.command.Gflag, "g", false, "selects alternate dump format") // not used
	flags.BoolVar(&f.command.Iflag, "i", false, "dumps multi-precision integers")
	flags.BoolVar(&f.command.Jflag, "j", false, "output with JSON format")
	flags.BoolVar(&f.command.Lflag, "l", false, "dumps literal packets (tag 11)")
	flags.BoolVar(&f.command.Mflag, "m", false, "dumps marker packets (tag 10)")
	flags.BoolVar(&f.command.Pflag, "p", false, "dumps private packets (tag 60-63)")
	flags.BoolVar(&f.command.Uflag, "u", false, "output UTC time")
	ftest := flags.Bool("ftest", false, "facade test")
	flags.Usage = func() {
		f.showUsage()
	}
	// Parse commandline flag
	if err := flags.Parse(args); err != nil {
		return ExitFailure, err
	}
	if f.command.Hflag {
		f.showUsage()
		return ExitSuccess, nil
	}
	if f.command.Vflag {
		f.showVersion()
		return ExitSuccess, nil
	}

	switch flags.NArg() {
	case 0:
		f.command.InputFile = ""
	case 1:
		f.command.InputFile = flags.Arg(0)
	default:
		return ExitFailure, os.ErrInvalid
	}

	if *ftest { // for facade test
		return ExitSuccess, ErrFacadeTest
	}
	if err := f.command.Run(); err != nil {
		return ExitFailure, err
	}
	return ExitSuccess, nil
}

func (f *Facade) showUsage() {
	usageText := `
USAGE:
   %s [options] [OpenPGP file]

OPTIONS:
   -h -- output this help
   -v -- output version
   -a -- accepts ASCII input only
   -i -- dumps multi-precision integers
   -j -- output with JSON format
   -l -- dumps literal packets (tag 11)
   -m -- dumps marker packets (tag 10)
   -p -- dumps private packets (tag 60-63)
   -u -- output UTC time
`
	f.OutputErrln(fmt.Sprintf(strings.Trim(usageText, " \t\n\r"), f.Name))
}

func (f *Facade) showVersion() {
	f.OutputErrln(fmt.Sprintf("%s %s", path.Base(f.Name), f.Version))
}
