package facade

import (
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/spiegel-im-spiegel/gocli"
	"github.com/spiegel-im-spiegel/gpgpdump/packets"
)

// Exit Code
const (
	ExitCodeOK    int = 0
	ExitCodeError int = iota
)

// Run Application
func Run(args []string, appName, version string, ui *gocli.UI) (int, error) {
	cmd := packets.Command(ui)

	flags := flag.NewFlagSet(appName, flag.ContinueOnError)
	flags.BoolVar(&cmd.Hflag, "h", false, "displays this help")
	flags.BoolVar(&cmd.Vflag, "v", false, "displays version")
	flags.BoolVar(&cmd.Aflag, "a", false, "accepts ASCII input only")
	flags.BoolVar(&cmd.Gflag, "g", false, "selects alternate dump format")
	flags.BoolVar(&cmd.Iflag, "i", false, "dumps integer packets")
	flags.BoolVar(&cmd.Lflag, "l", false, "dumps literal packets")
	flags.BoolVar(&cmd.Mflag, "m", false, "dumps marker packets")
	flags.BoolVar(&cmd.Pflag, "p", false, "dumps private packets")
	flags.BoolVar(&cmd.Uflag, "u", false, "displays UTC time")
	flags.Usage = func() {
		showUsage(ui, appName, version)
	}
	// Parse commandline flag
	if err := flags.Parse(args); err != nil {
		return ExitCodeError, nil
	}
	if cmd.Hflag {
		showUsage(ui, appName, version)
		return ExitCodeOK, nil
	}
	if cmd.Vflag {
		showVersion(ui, appName, version)
		return ExitCodeOK, nil
	}

	switch flags.NArg() {
	case 0:
		cmd.InputFile = ""
	case 1:
		cmd.InputFile = flags.Arg(0)
	default:
		return ExitCodeError, os.ErrInvalid
	}

	return cmd.Run()
}

func showUsage(ui *gocli.UI, name, version string) {
	usageText := `
USAGE:
   %s [options] [PGPfile]

VERSION:
   %s

OPTIONS:
   -h -- displays this help
   -v -- displays version
   -a -- accepts ASCII input only
   -g -- selects alternate dump format
   -i -- dumps integer packets
   -l -- dumps literal packets
   -m -- dumps marker packets
   -p -- dumps private packets
   -u -- displays UTC time
`
	ui.OutputErrln(fmt.Sprintf(usageText, name, version))
}

func showVersion(ui *gocli.UI, name, version string) {
	versionText := fmt.Sprintf("%s version %s", path.Base(name), version)
	ui.OutputErrln(versionText)
}
