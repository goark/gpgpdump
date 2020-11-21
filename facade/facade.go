package facade

import (
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gocli/exitcode"
	"github.com/spiegel-im-spiegel/gocli/rwi"
	"github.com/spiegel-im-spiegel/gpgpdump/parse"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
)

var (
	//Name is applicatin name
	Name = "gpgpdump"
	//Version is version for applicatin
	Version = "dev-version"
)

var (
	versionFlag bool //version flag
	jsonFlag    bool //output with JSON format
	debugFlag   bool //debug flag
	indentSize  int
	filePath    string
)

//newRootCmd returns cobra.Command instance for root command
func newRootCmd(ui *rwi.RWI, args []string) *cobra.Command {
	rootCmd := &cobra.Command{
		Use: Name,
		RunE: func(cmd *cobra.Command, args []string) error {
			//options options
			if versionFlag {
				return debugPrint(ui, errs.Wrap(ui.OutputErrln(getVersion())))
			}
			cxt := parseContext(cmd)

			//open PGP file
			r := ui.Reader()
			if len(filePath) > 0 {
				file, err := os.Open(filePath)
				if err != nil {
					return debugPrint(ui, errs.Wrap(err))
				}
				defer file.Close()
				r = file
			}

			//options OpenPGP packets
			p, err := parse.New(cxt, r)
			if err != nil {
				return debugPrint(ui, err)
			}
			res, err := p.Parse()
			if err != nil {
				return debugPrint(ui, err)
			}
			r, err = marshalPacketInfo(res)
			if err != nil {
				return debugPrint(ui, err)
			}
			return debugPrint(ui, errs.Wrap(ui.WriteFrom(r)))
		},
	}
	rootCmd.Flags().BoolVarP(&versionFlag, "version", "v", false, "output version of "+Name)
	rootCmd.Flags().StringVarP(&filePath, "file", "f", "", "path of OpenPGP file")
	rootCmd.PersistentFlags().BoolVarP(&jsonFlag, "json", "j", false, "output with JSON format")
	rootCmd.PersistentFlags().IntVarP(&indentSize, "indent", "", 0, "indent size for output string")
	rootCmd.PersistentFlags().BoolP(context.ARMOR.String(), "a", false, "accepts ASCII input only")
	rootCmd.PersistentFlags().BoolP(context.CERT.String(), "c", false, "dumps attested certification in signature packets (tag 2)")
	rootCmd.PersistentFlags().BoolP(context.DEBUG.String(), "", false, "for debug") //not use
	//rootCmd.PersistentFlags().BoolP(context.GDUMP.String(), "g", false, "selects alternate (GnuPG type) dump format") //not use
	rootCmd.PersistentFlags().BoolP(context.INTEGER.String(), "i", false, "dumps multi-precision integers")
	rootCmd.PersistentFlags().BoolP(context.LITERAL.String(), "l", false, "dumps literal packets (tag 11)")
	rootCmd.PersistentFlags().BoolP(context.MARKER.String(), "m", false, "dumps marker packets (tag 10)")
	rootCmd.PersistentFlags().BoolP(context.PRIVATE.String(), "p", false, "dumps private packets (tag 60-63)")
	rootCmd.PersistentFlags().BoolP(context.UTC.String(), "u", false, "output with UTC time")

	rootCmd.SilenceUsage = true
	rootCmd.SetArgs(args)
	rootCmd.SetIn(ui.Reader())       //Stdin
	rootCmd.SetOut(ui.ErrorWriter()) //Stdout -> Stderr
	rootCmd.SetErr(ui.ErrorWriter()) //Stderr
	rootCmd.AddCommand(
		newVersionCmd(ui),
		newHkpCmd(ui),
		newGitHubCmd(ui),
		newFetchCmd(ui),
	)

	return rootCmd
}

func marshalPacketInfo(i *result.Info) (io.Reader, error) {
	if jsonFlag {
		return i.JSON(indentSize)
	}
	if indentSize > 0 {
		return i.ToString(strings.Repeat(" ", indentSize)), nil
	}
	return i.ToString("\t"), nil
}

func getBool(cmd *cobra.Command, code context.OptCode) (context.OptCode, bool) {
	name := code.String()
	f, err := cmd.Flags().GetBool(name)
	if err != nil {
		panic("invalid option: " + name)
	}
	return code, f
}

func parseContext(cmd *cobra.Command) *context.Context {
	cxt := context.New(
		context.Set(getBool(cmd, context.ARMOR)),
		context.Set(getBool(cmd, context.CERT)),
		context.Set(getBool(cmd, context.DEBUG)), //for debug
		//context.Set(getBool(cmd, context.GDUMP)), //not use
		context.Set(getBool(cmd, context.INTEGER)),
		context.Set(getBool(cmd, context.LITERAL)),
		context.Set(getBool(cmd, context.MARKER)),
		context.Set(getBool(cmd, context.PRIVATE)),
		context.Set(getBool(cmd, context.UTC)),
	)
	debugFlag = cxt.Debug()
	return cxt
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

/* Copyright 2017-2020 Spiegel
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
