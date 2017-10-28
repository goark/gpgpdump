package gpgpdump

import (
	"fmt"
	"strings"

	"github.com/spiegel-im-spiegel/gpgpdump/options"
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
	reader      = strings.NewReader(openpgpStr)
	optionss    = options.NewOptions()
)

func ExampleParse() {
	info, err := Parse(reader, optionss)
	if err != nil {
		return
	}
	fmt.Println(info.Packets[0].Value)
	// Output:
	// Signature Packet (tag 2)
}

func ExampleParseByte() {
	info, err := ParseByte(openpgpData, optionss)
	if err != nil {
		return
	}
	fmt.Println(info.Packets[0].Value)
	// Output:
	// Signature Packet (tag 2)
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