package facade

import (
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/spiegel-im-spiegel/gocli"
	"github.com/spiegel-im-spiegel/gpgpdump"
	"github.com/spiegel-im-spiegel/gpgpdump/options"
)

var (
	//Name is applicatin name
	Name = "gpgpdump"
	//Version is version for applicatin
	Version string
)

var (
	versionFlag bool            //version flag
	jsonFlag    bool            //output with JSON format
	tomlFlag    bool            //output with TOML format
	cui         = gocli.NewUI() //CUI instance
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use: Name + " [flags] [OpenPGP file]",
	RunE: func(cmd *cobra.Command, args []string) error {
		//parse options
		if versionFlag {
			cui.OutputErr(Name)
			if len(Version) > 0 {
				cui.OutputErr(fmt.Sprintf(" v%s", Version))
			}
			cui.OutputErrln()
			cui.OutputErrln("Copyright 2016,2017 Spiegel (based on pgpdump by kazu-yamamoto)")
			cui.OutputErrln("Licensed under Apache License, Version 2.0")
			return nil
		}
		opts := parseOpt(cmd)

		//open PGP file
		reader := cui.Reader()
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
			return err
		}

		//marshal packet info
		var result io.Reader
		if jsonFlag {
			result, err = info.JSON()
		} else if tomlFlag {
			result, err = info.TOML()
		} else {
			result = info.ToString("\t")
			err = nil
		}
		if err != nil {
			return err
		}
		cui.WriteFrom(result)
		return nil
	},
}

func getBool(cmd *cobra.Command, name string) bool {
	f, err := cmd.Flags().GetBool(name)
	if err != nil {
		panic("invalid option: " + name)
	}
	return f
}

func parseOpt(cmd *cobra.Command) *options.Options {
	return options.New(
		options.Set(options.ArmorOpt, getBool(cmd, options.ArmorOpt)),
		options.Set(options.DebugOpt, getBool(cmd, options.DebugOpt)), //for debug
		//options.Set(options.GDumpOpt, getBool(cmd, options.GDumpOpt)), //not use
		options.Set(options.IntegerOpt, getBool(cmd, options.IntegerOpt)),
		options.Set(options.LiteralOpt, getBool(cmd, options.LiteralOpt)),
		options.Set(options.MarkerOpt, getBool(cmd, options.MarkerOpt)),
		options.Set(options.PrivateOpt, getBool(cmd, options.PrivateOpt)),
		options.Set(options.UTCOpt, getBool(cmd, options.UTCOpt)),
	)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(ui *gocli.UI, args []string) (exit ExitCode) {
	defer func() {
		//panic hundling
		if r := recover(); r != nil {
			cui.OutputErrln("Panic:", r)
			for depth := 0; ; depth++ {
				pc, src, line, ok := runtime.Caller(depth)
				if !ok {
					break
				}
				cui.OutputErrln(" ->", depth, ":", runtime.FuncForPC(pc).Name(), ":", src, ":", line)
			}
			exit = ExitAbnormal
		}
	}()

	//execution
	cui = ui
	rootCmd.SetArgs(args)
	rootCmd.SetOutput(ui.ErrorWriter())
	exit = ExitNormal
	if err := rootCmd.Execute(); err != nil {
		exit = ExitAbnormal
	}
	return
}

func init() {
	rootCmd.Flags().BoolVarP(&versionFlag, "version", "v", false, "output version of "+Name)
	rootCmd.Flags().BoolVarP(&jsonFlag, "json", "j", false, "output with JSON format")
	rootCmd.Flags().BoolVarP(&tomlFlag, "toml", "t", false, "output with TOML format")
	rootCmd.Flags().BoolP(options.ArmorOpt, "a", false, "accepts ASCII input only")
	rootCmd.Flags().BoolP(options.DebugOpt, "", false, "for debug") //not use
	//rootCmd.Flags().BoolP(options.GDumpOpt, "g", false, "selects alternate (GnuPG type) dump format") //not use
	rootCmd.Flags().BoolP(options.IntegerOpt, "i", false, "dumps multi-precision integers")
	rootCmd.Flags().BoolP(options.LiteralOpt, "l", false, "dumps literal packets (tag 11)")
	rootCmd.Flags().BoolP(options.MarkerOpt, "m", false, "dumps marker packets (tag 10)")
	rootCmd.Flags().BoolP(options.PrivateOpt, "p", false, "dumps private packets (tag 60-63)")
	rootCmd.Flags().BoolP(options.UTCOpt, "u", false, "output with UTC time")
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
