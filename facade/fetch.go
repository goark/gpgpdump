package facade

import (
	"context"
	"os"

	"github.com/goark/errs"

	"github.com/goark/fetch"
	"github.com/goark/gocli/rwi"
	"github.com/goark/gocli/signal"
	"github.com/goark/gpgpdump/parse"
	"github.com/spf13/cobra"
)

//newHkpCmd returns cobra.Command instance for show sub-command
func newFetchCmd(ui *rwi.RWI) *cobra.Command {
	fetchCmd := &cobra.Command{
		Use:     "fetch [flags] URL",
		Aliases: []string{"fch", "f"},
		Short:   "Dumps OpenPGP packets form the Web",
		Long:    "Dumps OpenPGP packets form the Web.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cxt := parseContext(cmd)
			//user id
			if len(args) != 1 {
				return debugPrint(ui, errs.Wrap(os.ErrInvalid, errs.WithContext("args", args)))
			}
			u, err := fetch.URL(args[0])
			if err != nil {
				return debugPrint(ui, err)
			}

			//options
			rawFlag, err := cmd.Flags().GetBool("raw")
			if err != nil {
				return debugPrint(ui, errs.New("error in --raw option", errs.WithCause(err)))
			}

			//Fetch OpenPGP packets
			resp, err := fetch.New().Get(
				u,
				fetch.WithContext(signal.Context(context.Background(), os.Interrupt)),
			)
			if err != nil {
				return debugPrint(ui, err)
			}
			defer resp.Close()
			if rawFlag {
				return debugPrint(ui, ui.WriteFrom(resp.Body()))
			}

			//parse OpenPGP packets
			p, err := parse.New(cxt, resp.Body())
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
	fetchCmd.Flags().BoolP("raw", "", false, "output raw data")

	return fetchCmd
}

/* Copyright 2019-2021 Spiegel
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
