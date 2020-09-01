package parse_test

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/parse"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
)

const (
	openpgpStr = `
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2

iF4EARMIAAYFAlTDCN8ACgkQMfv9qV+7+hg2HwEA6h2iFFuCBv3VrsSf2BREQaT1
T1ZprZqwRPOjiLJg9AwA/ArTwCPz7c2vmxlv7sRlRLUI6CdsOqhuO1KfYXrq7idI
=ZOTN
-----END PGP SIGNATURE-----
`
)

var (
	openpgpData = []byte(openpgpStr)
	cxt         = context.New()
)

func ExampleParse() {
	p, err := parse.NewBytes(cxt, openpgpData)
	if err != nil {
		return
	}
	info, err := p.Parse()
	if err != nil {
		return
	}
	if info != nil && len(info.Packets) > 0 {
		fmt.Println(info.Packets[0].Name)
	}
	// Output:
	// Signature Packet (tag 2)
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
