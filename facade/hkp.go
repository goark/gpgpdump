package facade

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gocli/rwi"
	"github.com/spiegel-im-spiegel/gocli/signal"
	"github.com/spiegel-im-spiegel/gpgpdump/ecode"
	"github.com/spiegel-im-spiegel/gpgpdump/hkp"
	"github.com/spiegel-im-spiegel/gpgpdump/parse"
)

//newHkpCmd returns cobra.Command instance for show sub-command
func newHkpCmd(ui *rwi.RWI) *cobra.Command {
	hkpCmd := &cobra.Command{
		Use:   "hkp [flags] <user ID or key ID>",
		Short: "Dumps from OpenPGP key server",
		Long:  "Dumps from OpenPGP key server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cxt := parseContext(cmd)
			//user id
			if len(args) == 0 {
				return debugPrint(ui, ecode.ErrUserID)
			}
			userID := args[0]

			//Create context
			ctx := signal.Context(context.Background(), os.Interrupt)

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
			prt := hkp.HKP
			if secFlag {
				prt = hkp.HKPS
			}
			resp, err := hkp.New(
				sks,
				hkp.WithProtocol(prt),
				hkp.WithPort(port),
			).Client(ctx, &http.Client{}).Get(userID)
			if err != nil {
				if errors.Is(err, ecode.ErrArmorText) {
					return debugPrint(ui, ui.WriteFrom(bytes.NewReader(resp)))
				}
				return debugPrint(ui, err)
			}
			if rawFlag {
				return debugPrint(ui, ui.WriteFrom(bytes.NewReader(resp)))
			}

			//parse OpenPGP packets
			p, err := parse.NewBytes(resp, cxt)
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

/* Copyright 2019,2020 Spiegel
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
