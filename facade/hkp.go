package facade

import (
	"os"

	"github.com/goark/errs"

	"github.com/goark/fetch"
	"github.com/goark/gocli/rwi"
	"github.com/goark/gpgpdump/ecode"
	"github.com/goark/gpgpdump/hkp"
	"github.com/goark/gpgpdump/parse"
	contxt "github.com/goark/gpgpdump/parse/context"
	"github.com/spf13/cobra"
)

// newHkpCmd returns cobra.Command instance for show sub-command
func newHkpCmd(ui *rwi.RWI) *cobra.Command {
	hkpCmd := &cobra.Command{
		Use:     "hkp [flags] {userID | keyID}",
		Aliases: []string{"h"},
		Short:   "Dumps OpenPGP packets from the key server",
		Long:    "Dumps OpenPGP packets from the key server.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cxt := parseContext(cmd)
			cxt.Set(contxt.ARMOR, true)
			//user id
			if len(args) != 1 {
				return debugPrint(ui, errs.Wrap(os.ErrInvalid, errs.WithContext("args", args)))
			}
			userID := args[0]

			//options
			sks, err := cmd.Flags().GetString("keyserver")
			if err != nil {
				return debugPrint(ui, errs.New("error in --keyserver option", errs.WithCause(err)))
			}
			if len(sks) == 0 {
				return debugPrint(ui, errs.New("error in --keyserver option", errs.WithCause(ecode.ErrEmptyKeyServer)))
			}
			port, err := cmd.Flags().GetInt("port")
			if err != nil {
				return debugPrint(ui, errs.New("error in --port option", errs.WithCause(err)))
			}
			rawFlag, err := cmd.Flags().GetBool("raw")
			if err != nil {
				return debugPrint(ui, errs.New("error in --raw option", errs.WithCause(err)))
			}
			secFlag, err := cmd.Flags().GetBool("secure")
			if err != nil {
				return debugPrint(ui, errs.New("error in --secure option", errs.WithCause(err)))
			}

			//Fetch OpenPGP packets
			prt := hkp.HKP
			if secFlag {
				prt = hkp.HKPS
			}
			resp, err := hkp.New(
				sks,
				hkp.WithProtocol(prt),
				hkp.WithPort(port),
			).Fetch(
				cmd.Context(),
				fetch.New(),
				userID,
			)
			if err != nil {
				return debugPrint(ui, err)
			}
			defer resp.Close()
			if rawFlag {
				return debugPrint(ui, ui.WriteFrom(resp))
			}

			//parse OpenPGP packets
			p, err := parse.New(cxt, resp)
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
	hkpCmd.Flags().StringP("keyserver", "", "keys.gnupg.net", "OpenPGP key server")
	hkpCmd.Flags().IntP("port", "", 11371, "port number of OpenPGP key server")
	hkpCmd.Flags().BoolP("secure", "", false, "enable HKP over HTTPS")
	hkpCmd.Flags().BoolP("raw", "", false, "output raw text from OpenPGP key server")

	return hkpCmd
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
