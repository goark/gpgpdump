package facade

import (
	cntxt "context"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/goark/errs"

	"github.com/goark/gocli/exitcode"
	"github.com/goark/gocli/rwi"
	"github.com/goark/gpgpdump/ecode"
	"github.com/goark/gpgpdump/facade/clipboard"
	"github.com/goark/gpgpdump/parse"
	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/spf13/cobra"
)

var (
	// Name is application name.
	Name = "gpgpdump"
	// Version is application version.
	Version = "dev-version"
)

var (
	versionFlag bool //version flag
	jsonFlag    bool //output with JSON format
	cbFlag      bool //input from clipboard
	debugFlag   bool //debug flag
	indentSize  int
	filePath    string
)

// newRootCmd builds the CLI command tree and keeps packet decoding in parse packages.
func newRootCmd(ui *rwi.RWI, args []string) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   Name,
		Short: "OpenPGP packet visualizer",
		Long:  "OpenPGP (RFC 9580) packet visualizer by golang.",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			//options options
			if versionFlag {
				return debugPrint(ui, errs.Wrap(ui.OutputErrln(getVersion())))
			}
			cxt, err := parseContext(cmd)
			if err != nil {
				return debugPrint(ui, err)
			}

			//open PGP file
			if cbFlag && len(filePath) > 0 {
				return debugPrint(ui, errs.Wrap(ecode.ErrClipboard))
			}
			var r io.Reader
			switch {
			case cbFlag:
				cb, err := clipboard.NewReader()
				if err != nil {
					return debugPrint(ui, errs.Wrap(err))
				}
				r = cb
				cxt.Set(context.ARMOR, true) //ASCII armor text only
			case len(filePath) > 0:
				file, err := os.Open(filepath.Clean(filePath))
				if err != nil {
					return debugPrint(ui, errs.Wrap(err))
				}
				defer func() {
					if cerr := file.Close(); cerr != nil {
						err = debugPrint(ui, errs.Wrap(cerr))
					}
				}()
				r = file
			default:
				r = ui.Reader()
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
	_ = rootCmd.MarkFlagFilename("file")
	rootCmd.Flags().BoolVarP(&cbFlag, "clipboard", "", false, "input from clipboard (ASCII armor text only)")
	rootCmd.PersistentFlags().BoolVarP(&jsonFlag, "json", "j", false, "output with JSON format")
	rootCmd.PersistentFlags().IntVarP(&indentSize, "indent", "", 0, "indent size for output text")
	rootCmd.PersistentFlags().BoolP(context.ARMOR.String(), "a", false, "accepts ASCII armor text only")
	rootCmd.PersistentFlags().BoolP(context.CERT.String(), "c", false, "dumps attested certification in signature packets (tag 2)")
	rootCmd.PersistentFlags().BoolP(context.DEBUG.String(), "", false, "for debug") //not use
	//rootCmd.PersistentFlags().BoolP(context.GDUMP.String(), "g", false, "selects alternate (GnuPG type) dump format") //not use
	rootCmd.PersistentFlags().BoolP(context.INTEGER.String(), "i", false, "dumps multi-precision integers")
	rootCmd.PersistentFlags().BoolP(context.LITERAL.String(), "l", false, "dumps literal packets (tag 11)")
	rootCmd.PersistentFlags().BoolP(context.MARKER.String(), "m", false, "dumps marker packets (tag 10)")
	rootCmd.PersistentFlags().BoolP(context.PRIVATE.String(), "p", false, "dumps private packets (tag 60-63)")
	rootCmd.PersistentFlags().BoolP(context.UTC.String(), "u", false, "output with UTC time")

	rootCmd.SilenceUsage = true
	rootCmd.CompletionOptions.DisableDefaultCmd = true
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

// getBool returns a parsed bool flag value for a parse option.
func getBool(cmd *cobra.Command, code context.OptCode) (context.OptCode, bool, error) {
	name := code.String()
	f, err := cmd.Flags().GetBool(name)
	if err != nil {
		return code, false, errs.Wrap(ecode.ErrInvalidOption, errs.WithCause(err), errs.WithContext("option", name))
	}
	return code, f, nil
}

// parseContext builds parser context from CLI flags.
func parseContext(cmd *cobra.Command) (*context.Context, error) {
	armorCode, armor, err := getBool(cmd, context.ARMOR)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	certCode, cert, err := getBool(cmd, context.CERT)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	debugCode, debug, err := getBool(cmd, context.DEBUG)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	integerCode, integer, err := getBool(cmd, context.INTEGER)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	literalCode, literal, err := getBool(cmd, context.LITERAL)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	markerCode, marker, err := getBool(cmd, context.MARKER)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	privateCode, private, err := getBool(cmd, context.PRIVATE)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	utcCode, utc, err := getBool(cmd, context.UTC)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	cxt := context.New(
		context.Set(armorCode, armor),
		context.Set(certCode, cert),
		context.Set(debugCode, debug), //for debug
		//context.Set(getBool(cmd, context.GDUMP)), //not use
		context.Set(integerCode, integer),
		context.Set(literalCode, literal),
		context.Set(markerCode, marker),
		context.Set(privateCode, private),
		context.Set(utcCode, utc),
	)
	debugFlag = cxt.Debug()
	return cxt, nil
}

// Execute is the top-level CLI entry point called from main.
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

	// create interrupt SIGNAL
	ctx, cancel := signal.NotifyContext(cntxt.Background(), os.Interrupt)
	defer cancel()

	//execution
	exit = exitcode.Normal
	if err := newRootCmd(ui, args).ExecuteContext(ctx); err != nil {
		exit = exitcode.Abnormal
	}
	return
}

/* Copyright 2017-2026 Spiegel
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
