package pubkey

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
)

var (
	pubkeySig19      = []byte{0x01, 0x00, 0xea, 0x1d, 0xa2, 0x14, 0x5b, 0x82, 0x06, 0xfd, 0xd5, 0xae, 0xc4, 0x9f, 0xd8, 0x14, 0x44, 0x41, 0xa4, 0xf5, 0x4f, 0x56, 0x69, 0xad, 0x9a, 0xb0, 0x44, 0xf3, 0xa3, 0x88, 0xb2, 0x60, 0xf4, 0x0c, 0x00, 0xfc, 0x0a, 0xd3, 0xc0, 0x23, 0xf3, 0xed, 0xcd, 0xaf, 0x9b, 0x19, 0x6f, 0xee, 0xc4, 0x65, 0x44, 0xb5, 0x08, 0xe8, 0x27, 0x6c, 0x3a, 0xa8, 0x6e, 0x3b, 0x52, 0x9f, 0x61, 0x7a, 0xea, 0xee, 0x27, 0x48}
	pubkeySig22      = []byte{0x00, 0xfd, 0x17, 0xe2, 0xb2, 0xa9, 0xa4, 0xdd, 0x49, 0x9c, 0x67, 0xe8, 0xa2, 0x9d, 0x82, 0xb7, 0x0e, 0x8a, 0xe9, 0xee, 0xc4, 0x0d, 0x69, 0x67, 0xf6, 0xcf, 0xd9, 0x36, 0x01, 0x58, 0xb5, 0xe8, 0x8a, 0xb4, 0x00, 0xfb, 0x04, 0xe6, 0xf4, 0xad, 0x9a, 0x49, 0xcf, 0x58, 0xba, 0x56, 0xc9, 0x70, 0x51, 0x77, 0x5c, 0xa4, 0x09, 0x0f, 0x3b, 0xca, 0x78, 0x3c, 0xa4, 0x9e, 0x89, 0x3e, 0x4d, 0x5c, 0xd8, 0x21, 0x53, 0x08}
	pubkeySigUnknown = []byte{0x01, 0x02, 0x03, 0x04}
)

const (
	pubkeySigResult19 = `
	ECDSA value r (256 bits)
		ea 1d a2 14 5b 82 06 fd d5 ae c4 9f d8 14 44 41 a4 f5 4f 56 69 ad 9a b0 44 f3 a3 88 b2 60 f4 0c
	ECDSA value s (252 bits)
		0a d3 c0 23 f3 ed cd af 9b 19 6f ee c4 65 44 b5 08 e8 27 6c 3a a8 6e 3b 52 9f 61 7a ea ee 27 48
`
	pubkeySigResult22 = `
	EC point r (253 bits)
		17 e2 b2 a9 a4 dd 49 9c 67 e8 a2 9d 82 b7 0e 8a e9 ee c4 0d 69 67 f6 cf d9 36 01 58 b5 e8 8a b4
	EdDSA value s in the little endian representation (251 bits)
		04 e6 f4 ad 9a 49 cf 58 ba 56 c9 70 51 77 5c a4 09 0f 3b ca 78 3c a4 9e 89 3e 4d 5c d8 21 53 08
`
	pubkeySigResultUnknown = `
	Multi-precision integers of Unknown (pub 99) (4 bytes)
		01 02 03 04
`
)

func TestPubkeySig(t *testing.T) {
	testCases := []struct {
		pubID   uint8
		content []byte
		res     string
	}{
		{pubID: 19, content: pubkeySig19, res: pubkeySigResult19},
		{pubID: 22, content: pubkeySig22, res: pubkeySigResult22},
		{pubID: 99, content: pubkeySigUnknown, res: pubkeySigResultUnknown},
	}
	for _, tc := range testCases {
		parent := result.NewItem()
		cxt := context.New(
			context.Set(context.DEBUG, true),
			context.Set(context.GDUMP, true),
			context.Set(context.INTEGER, true),
			context.Set(context.LITERAL, true),
			context.Set(context.MARKER, true),
			context.Set(context.PRIVATE, true),
			context.Set(context.UTC, true),
		)
		if err := New(cxt, values.PubID(tc.pubID), reader.New(tc.content)).ParseSig(parent); err != nil {
			t.Errorf("Parse() = %+v, want nil error.", err)
		}
		str := parent.String()
		if str != tc.res {
			t.Errorf("Parse() = \"%v\", want \"%v\".", str, tc.res)
		}
	}
}

/* Copyright 2016-2020 Spiegel
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
