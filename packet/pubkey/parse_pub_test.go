package pubkey

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/options"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

var (
	pubkeyPub19      = []byte{0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x02, 0x03, 0x04, 0xa5, 0xd5, 0xbc, 0x76, 0x07, 0xdb, 0xb8, 0x8f, 0xb2, 0x21, 0x19, 0x11, 0xb0, 0xd0, 0x5a, 0x7e, 0xe9, 0x34, 0xdf, 0xa3, 0x8d, 0x8e, 0xf9, 0xb9, 0x7e, 0xb6, 0xd8, 0x63, 0x0a, 0xee, 0x92, 0xee, 0x0d, 0x74, 0xc7, 0xc0, 0x48, 0xf3, 0xb8, 0xd5, 0xaa, 0xa8, 0x73, 0xbd, 0xe7, 0x19, 0xb5, 0xda, 0xd8, 0xf6, 0x68, 0x05, 0x03, 0x15, 0x7d, 0x9a, 0x84, 0x43, 0x61, 0xca, 0xee, 0xdf, 0xd6, 0x0e}
	pubkeyPub22      = []byte{0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01, 0x01, 0x07, 0x40, 0xc6, 0xae, 0xd8, 0x56, 0x62, 0x34, 0x73, 0xe7, 0xf1, 0x86, 0xff, 0x5f, 0x09, 0xdd, 0xd2, 0xc2, 0xb5, 0x48, 0xbd, 0x78, 0x94, 0x90, 0xa8, 0xd2, 0xfd, 0x9c, 0xfc, 0xc6, 0x69, 0x15, 0xfb, 0x86}
	pubkeyPubUnknown = []byte{0x01, 0x02, 0x03, 0x04}
)

const (
	pubkeyPubResult19 = `
	ECC Curve OID: nistp256 (256bits key size)
		2a 86 48 ce 3d 03 01 07
	ECDSA EC point (uncompressed format) (515 bits)
		04 a5 d5 bc 76 07 db b8 8f b2 21 19 11 b0 d0 5a 7e e9 34 df a3 8d 8e f9 b9 7e b6 d8 63 0a ee 92 ee 0d 74 c7 c0 48 f3 b8 d5 aa a8 73 bd e7 19 b5 da d8 f6 68 05 03 15 7d 9a 84 43 61 ca ee df d6 0e
`
	pubkeyPubResult22 = `
	ECC Curve OID: ed25519 (256bits key size)
		2b 06 01 04 01 da 47 0f 01
	EdDSA EC point (Native point format of the curve follows) (263 bits)
		40 c6 ae d8 56 62 34 73 e7 f1 86 ff 5f 09 dd d2 c2 b5 48 bd 78 94 90 a8 d2 fd 9c fc c6 69 15 fb 86
`
	pubkeyPubResultUnknown = `
	Multi-precision integers of Unknown (pub 99) (4 bytes)
		01 02 03 04
`
)

func TestPubkeyPub(t *testing.T) {
	testCases := []struct {
		pubID   uint8
		content []byte
		res     string
	}{
		{pubID: 19, content: pubkeyPub19, res: pubkeyPubResult19},
		{pubID: 22, content: pubkeyPub22, res: pubkeyPubResult22},
		{pubID: 99, content: pubkeyPubUnknown, res: pubkeyPubResultUnknown},
	}
	for _, tc := range testCases {
		parent := info.NewItem()
		cxt := context.New(options.New(
			options.Set(options.DEBUG, true),
			options.Set(options.GDUMP, true),
			options.Set(options.INTEGER, true),
			options.Set(options.LITERAL, true),
			options.Set(options.MARKER, true),
			options.Set(options.PRIVATE, true),
			options.Set(options.UTC, true),
		))
		if err := New(cxt, values.PubID(tc.pubID), reader.New(tc.content)).ParsePub(parent); err != nil {
			t.Errorf("Parse() = %+v, want nil error.", err)
		}
		str := parent.String()
		if str != tc.res {
			t.Errorf("Parse() = \"%v\", want \"%v\".", str, tc.res)
		}
	}
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
