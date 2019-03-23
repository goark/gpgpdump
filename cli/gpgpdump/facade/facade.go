package facade

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spiegel-im-spiegel/gocli/exitcode"
	"github.com/spiegel-im-spiegel/gocli/rwi"
	"github.com/spiegel-im-spiegel/gpgpdump"
	"github.com/spiegel-im-spiegel/gpgpdump/options"
)

var (
	//Name is applicatin name
	Name = "gpgpdump"
	//Version is version for applicatin
	Version = "dev-version"
)

var (
	usage = []string{ //output message of version
		Name + " " + Version,
		"Copyright 2016-2019 Spiegel (based on pgpdump by kazu-yamamoto)",
		"Licensed under Apache License, Version 2.0",
	}
	versionFlag bool //version flag
	jsonFlag    bool //output with JSON format
	tomlFlag    bool //output with TOML format
	indentSize  int
)

//newRootCmd returns cobra.Command instance for root command
func newRootCmd(ui *rwi.RWI, args []string) *cobra.Command {
	rootCmd := &cobra.Command{
		Use: Name + " [flags] [OpenPGP file]",
		RunE: func(cmd *cobra.Command, args []string) error {
			//parse options
			if versionFlag {
				return ui.OutputErrln(strings.Join(usage, "\n"))
			}
			opts := parseOpt(cmd)

			//open PGP file
			reader := ui.Reader()
			if len(args) > 0 {
				file, err := os.Open(args[0]) //args[0] is maybe file path
				if err != nil {
					return err
				}
				defer file.Close()
				reader = file
			}

			//parse OpenPGP packets
			info, err := gpgpdump.Parse(reader, opts)
			if err != nil {
				if opts.Debug() {
					_ = ui.OutputErrln(fmt.Sprintf("%+v", err))
				}
				return err
			}

			//marshal packet info
			var result io.Reader
			if jsonFlag {
				result, err = info.JSON(indentSize)
			} else if tomlFlag {
				result, err = info.TOML(indentSize)
			} else if indentSize > 0 {
				result = info.ToString(strings.Repeat(" ", indentSize))
				err = nil
			} else {
				result = info.ToString("\t")
				err = nil
			}
			if err != nil {
				if opts.Debug() {
					_ = ui.OutputErrln(fmt.Sprintf("%+v", err))
				}
				return err
			}
			return ui.WriteFrom(result)
		},
	}
	rootCmd.Flags().BoolVarP(&versionFlag, "version", "v", false, "output version of "+Name)
	rootCmd.Flags().BoolVarP(&jsonFlag, "json", "j", false, "output with JSON format")
	rootCmd.Flags().BoolVarP(&tomlFlag, "toml", "t", false, "output with TOML format")
	rootCmd.Flags().IntVarP(&indentSize, "indent", "", 0, "indent size for output string")
	rootCmd.Flags().BoolP(options.ARMOR.String(), "a", false, "accepts ASCII input only")
	rootCmd.Flags().BoolP(options.DEBUG.String(), "", false, "for debug") //not use
	//rootCmd.Flags().BoolP(options.GDUMP.String(), "g", false, "selects alternate (GnuPG type) dump format") //not use
	rootCmd.Flags().BoolP(options.INTEGER.String(), "i", false, "dumps multi-precision integers")
	rootCmd.Flags().BoolP(options.LITERAL.String(), "l", false, "dumps literal packets (tag 11)")
	rootCmd.Flags().BoolP(options.MARKER.String(), "m", false, "dumps marker packets (tag 10)")
	rootCmd.Flags().BoolP(options.PRIVATE.String(), "p", false, "dumps private packets (tag 60-63)")
	rootCmd.Flags().BoolP(options.UTC.String(), "u", false, "output with UTC time")

	rootCmd.SetArgs(args)
	rootCmd.SetOutput(ui.ErrorWriter())

	return rootCmd
}

func getBool(cmd *cobra.Command, code options.OptCode) (options.OptCode, bool) {
	name := code.String()
	f, err := cmd.Flags().GetBool(name)
	if err != nil {
		panic("invalid option: " + name)
	}
	return code, f
}

func parseOpt(cmd *cobra.Command) options.Options {
	return options.New(
		options.Set(getBool(cmd, options.ARMOR)),
		options.Set(getBool(cmd, options.DEBUG)), //for debug
		//options.Set(getBool(cmd, options.GDUMP)), //not use
		options.Set(getBool(cmd, options.INTEGER)),
		options.Set(getBool(cmd, options.LITERAL)),
		options.Set(getBool(cmd, options.MARKER)),
		options.Set(getBool(cmd, options.PRIVATE)),
		options.Set(getBool(cmd, options.UTC)),
	)
}

//Execute is called from main function
func Execute(ui *rwi.RWI, args []string) (exit exitcode.ExitCode) {
	defer func() {
		//panic hundling
		if r := recover(); r != nil {
			_ = ui.OutputErrln("Panic:", r)
			for depth := 0; ; depth++ {
				pc, src, line, ok := runtime.Caller(depth)
				if !ok {
					break
				}
				_ = ui.OutputErrln(" ->", depth, ":", runtime.FuncForPC(pc).Name(), ":", src, ":", line)
			}
			exit = exitcode.Abnormal
		}
	}()

	//execution
	exit = exitcode.Normal
	if err := newRootCmd(ui, args).Execute(); err != nil {
		exit = exitcode.Abnormal
	}
	return
}

/* Copyright 2017-2019 Spiegel
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
