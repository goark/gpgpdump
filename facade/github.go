package facade

import (
	"bytes"
	"os"

	"github.com/goark/errs"

	"github.com/goark/fetch"
	"github.com/goark/gocli/rwi"
	"github.com/goark/gpgpdump/github"
	"github.com/goark/gpgpdump/parse"
	contxt "github.com/goark/gpgpdump/parse/context"
	"github.com/spf13/cobra"
)

// newHkpCmd returns cobra.Command instance for show sub-command
func newGitHubCmd(ui *rwi.RWI) *cobra.Command {
	githubCmd := &cobra.Command{
		Use:     "github [flags] GitHubUserID",
		Aliases: []string{"gh", "g"},
		Short:   "Dumps OpenPGP keys registered on GitHub",
		Long:    "Dumps OpenPGP keys registered on GitHub.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cxt := parseContext(cmd)
			cxt.Set(contxt.ARMOR, true)
			//user id
			if len(args) != 1 {
				return debugPrint(ui, errs.Wrap(os.ErrInvalid, errs.WithContext("args", args)))
			}
			userID := args[0]

			//options
			keyid, err := cmd.Flags().GetString("keyid")
			if err != nil {
				return debugPrint(ui, errs.New("error in --keyid option", errs.WithCause(err)))
			}
			rawFlag, err := cmd.Flags().GetBool("raw")
			if err != nil {
				return debugPrint(ui, errs.New("error in --raw option", errs.WithCause(err)))
			}

			//Fetch OpenPGP packets
			resp, err := github.GetKey(
				cmd.Context(),
				fetch.New(),
				userID,
				keyid,
			)
			if err != nil {
				return debugPrint(ui, err)
			}
			if rawFlag {
				return debugPrint(ui, ui.WriteFrom(bytes.NewReader(resp)))
			}

			//parse OpenPGP packets
			p, err := parse.NewBytes(cxt, resp)
			if err != nil {
				return debugPrint(ui, err)
			}
			res, err := p.Parse()
			if err != nil {
				return debugPrint(ui, err)
			}
			r, err := marshalPacketInfo(res)
			if err != nil {
				return debugPrint(ui, err)
			}
			return debugPrint(ui, ui.WriteFrom(r))
		},
	}
	githubCmd.Flags().StringP("keyid", "", "", "OpenPGP key ID")
	githubCmd.Flags().BoolP("raw", "", false, "output raw text (ASCII armor text)")

	return githubCmd
}

/* Copyright 2019-2023 Spiegel
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
