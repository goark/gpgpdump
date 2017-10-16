package facade

import (
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/spiegel-im-spiegel/gocli"
	"github.com/spiegel-im-spiegel/gpgpdump"
)

const (
	//Name is applicatin name
	Name = "gpgpdump"
	//Version is version for applicatin
	Version = "v0.2.0dev"
)

//ExitCode is OS exit code enumeration class
type ExitCode int

const (
	//Normal is OS exit code "normal"
	Normal ExitCode = iota
	//Abnormal is OS exit code "abnormal"
	Abnormal
)

//Int convert integer value
func (c ExitCode) Int() int {
	return int(c)
}

//Stringer method
func (c ExitCode) String() string {
	switch c {
	case Normal:
		return "normal end"
	case Abnormal:
		return "abnormal end"
	default:
		return "unknown"
	}
}

var (
	versionFlag bool      //version flag
	reader      io.Reader //input reader (maybe os.Stdin)
	result      string    //result by parsing OpenPGP packets
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use: Name + " [flags] [PGPfile]",
	RunE: func(cmd *cobra.Command, args []string) error {
		//parse options
		if versionFlag {
			return nil
		}
		opts := parseOpt(cmd)

		//open PGP file
		if len(args) > 0 {
			file, err := os.Open(args[0]) //args[0] is maybe file path
			if err != nil {
				return err
			}
			defer file.Close()
			reader = file
		}

		//parse OpenPGP packets
		p := gpgpdump.NewParse(opts, reader)
		info, err := p.Run()
		if err != nil {
			return err
		}

		//marshal packet info
		if opts.JSON() {
			result, err = info.JSON()
		} else {
			result, err = info.TOML()
		}
		if err != nil {
			return err
		}
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(cui *gocli.UI) (exit ExitCode) {
	defer func() {
		//panic hundling
		if r := recover(); r != nil {
			cui.OutputErrln("Panic:", r)
			for depth := 0; ; depth++ {
				pc, _, line, ok := runtime.Caller(depth)
				if !ok {
					break
				}
				cui.OutputErrln(" ->", depth, ":", runtime.FuncForPC(pc).Name(), ": line", line)
			}
			exit = Abnormal
		}
	}()

	//execution
	exit = Normal
	reader = cui.Reader() //default reader; maybe os.Stdin
	result = ""
	if err := RootCmd.Execute(); err != nil {
		//cui.OutputErrln(err) //no need to output error
		exit = Abnormal
		return
	}
	if versionFlag {
		cui.OutputErrln(version())
		return
	}
	cui.Outputln(result)
	return
}

func init() {
	RootCmd.Flags().BoolVarP(&versionFlag, "version", "v", false, "version for "+Name)
	RootCmd.Flags().BoolP(gpgpdump.ArmorOpt, "a", false, "accepts ASCII input only")
	//RootCmd.Flags().BoolP(gpgpdump.DebugOpt, "d", false, "for debug") //not use
	//RootCmd.Flags().BoolP(gpgpdump.GDumpOpt, "g", false, "selects alternate (GnuPG type) dump format") //not use
	RootCmd.Flags().BoolP(gpgpdump.IntegerOpt, "i", false, "dumps multi-precision integers")
	RootCmd.Flags().BoolP(gpgpdump.JSONOpt, "j", false, "output with JSON format")
	RootCmd.Flags().BoolP(gpgpdump.LiteralOpt, "l", false, "dumps literal packets (tag 11)")
	RootCmd.Flags().BoolP(gpgpdump.MarkerOpt, "m", false, "dumps marker packets (tag 10)")
	RootCmd.Flags().BoolP(gpgpdump.PrivateOpt, "p", false, "dumps private packets (tag 60-63)")
	RootCmd.Flags().BoolP(gpgpdump.UTCOpt, "u", false, "output UTC time")
}

func getBool(cmd *cobra.Command, name string) bool {
	f, err := cmd.Flags().GetBool(name)
	if err != nil {
		panic("invalid option: " + name)
	}
	return f
}

func parseOpt(cmd *cobra.Command) *gpgpdump.Options {
	return gpgpdump.NewOptions(
		gpgpdump.Set(gpgpdump.ArmorOpt, getBool(cmd, gpgpdump.ArmorOpt)),
		//gpgpdump.Set(gpgpdump.DebugOpt, getBool(cmd, gpgpdump.DebugOpt)), //not use
		//gpgpdump.Set(gpgpdump.GDumpOpt, getBool(cmd, gpgpdump.GDumpOpt)), //not use
		gpgpdump.Set(gpgpdump.IntegerOpt, getBool(cmd, gpgpdump.IntegerOpt)),
		gpgpdump.Set(gpgpdump.JSONOpt, getBool(cmd, gpgpdump.JSONOpt)),
		gpgpdump.Set(gpgpdump.LiteralOpt, getBool(cmd, gpgpdump.LiteralOpt)),
		gpgpdump.Set(gpgpdump.MarkerOpt, getBool(cmd, gpgpdump.MarkerOpt)),
		gpgpdump.Set(gpgpdump.PrivateOpt, getBool(cmd, gpgpdump.PrivateOpt)),
		gpgpdump.Set(gpgpdump.UTCOpt, getBool(cmd, gpgpdump.UTCOpt)),
	)
}

func version() string {
	return fmt.Sprintf("%s %s\nCopyright 2016,2017 Spiegel (based on pgpdump by kazu-yamamoto)\nLicensed under Apache License, Version 2.0\n", Name, Version)
}

/* Copyright 2017 Spiegel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
