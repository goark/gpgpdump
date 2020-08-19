package tags

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
	"golang.org/x/crypto/openpgp/packet"
)

var (
	tag01Body = []byte{0x03, 0xee, 0x06, 0x6b, 0xfe, 0x25, 0x2c, 0x4d, 0x79, 0x12, 0x02, 0x03, 0x04, 0xc3, 0xe7, 0xd7, 0x2b, 0xaf, 0x25, 0x2a, 0x19, 0xf6, 0x27, 0x80, 0xea, 0x7c, 0x4f, 0x6d, 0xca, 0x61, 0x22, 0x5a, 0xe3, 0xad, 0x0c, 0xfb, 0xd9, 0xa2, 0xd5, 0xa4, 0x30, 0x9a, 0xf3, 0xee, 0x34, 0x54, 0xae, 0xa8, 0xf6, 0x46, 0xac, 0x8a, 0xae, 0x38, 0xa6, 0x4f, 0xf3, 0xf2, 0xee, 0x30, 0x40, 0x62, 0x5b, 0x07, 0xe7, 0x2b, 0xee, 0x9a, 0x90, 0xd4, 0x6f, 0x1e, 0xd7, 0xc3, 0x26, 0x21, 0xab, 0x30, 0x4a, 0xfe, 0x88, 0xa2, 0x9f, 0x0e, 0xab, 0xf3, 0xbe, 0x7a, 0x89, 0x27, 0x32, 0x38, 0xb8, 0x06, 0x75, 0xfc, 0xac, 0x3c, 0xd4, 0xba, 0x0f, 0x49, 0x64, 0x15, 0xaa, 0x48, 0x9a, 0xdb, 0xc1, 0x8a, 0x7b, 0x11, 0x76, 0xfb, 0x2f, 0xef, 0xef, 0xb0, 0x29, 0xa9, 0x24, 0x75, 0x6d, 0x69, 0x12, 0x4d}
)

const (
	tag01Redult = `Public-Key Encrypted Session Key Packet (tag 1) (126 bytes)
	03 ee 06 6b fe 25 2c 4d 79 12 02 03 04 c3 e7 d7 2b af 25 2a 19 f6 27 80 ea 7c 4f 6d ca 61 22 5a e3 ad 0c fb d9 a2 d5 a4 30 9a f3 ee 34 54 ae a8 f6 46 ac 8a ae 38 a6 4f f3 f2 ee 30 40 62 5b 07 e7 2b ee 9a 90 d4 6f 1e d7 c3 26 21 ab 30 4a fe 88 a2 9f 0e ab f3 be 7a 89 27 32 38 b8 06 75 fc ac 3c d4 ba 0f 49 64 15 aa 48 9a db c1 8a 7b 11 76 fb 2f ef ef b0 29 a9 24 75 6d 69 12 4d
	Version: 3 (current)
		03
	Key ID: 0xee066bfe252c4d79
	Public-key Algorithm: ECDH public key algorithm (pub 18)
		12
	ECDH EC point (uncompressed format) (515 bits)
		04 c3 e7 d7 2b af 25 2a 19 f6 27 80 ea 7c 4f 6d ca 61 22 5a e3 ad 0c fb d9 a2 d5 a4 30 9a f3 ee 34 54 ae a8 f6 46 ac 8a ae 38 a6 4f f3 f2 ee 30 40 62 5b 07 e7 2b ee 9a 90 d4 6f 1e d7 c3 26 21 ab
	symmetric key (encoded) (48 bytes)
		4a fe 88 a2 9f 0e ab f3 be 7a 89 27 32 38 b8 06 75 fc ac 3c d4 ba 0f 49 64 15 aa 48 9a db c1 8a 7b 11 76 fb 2f ef ef b0 29 a9 24 75 6d 69 12 4d
`
)

func TestTag01(t *testing.T) {
	testCases := []struct {
		tag     uint8
		content []byte
		ktm     []byte
		cxt     context.SymAlgMode
		res     string
	}{
		{tag: 1, content: tag01Body, ktm: nil, cxt: context.ModePubEnc, res: tag01Redult},
	}
	for _, tc := range testCases {
		op := &packet.OpaquePacket{Tag: tc.tag, Contents: tc.content}
		cxt := context.New(
			context.Set(context.DEBUG, true),
			context.Set(context.GDUMP, true),
			context.Set(context.INTEGER, true),
			context.Set(context.LITERAL, true),
			context.Set(context.MARKER, true),
			context.Set(context.PRIVATE, true),
			context.Set(context.UTC, true),
		)
		if tc.ktm != nil {
			tm, _ := values.NewDateTime(reader.New(tc.ktm), cxt.UTC())
			cxt.KeyCreationTime = tm
		}
		i, err := NewTag(op, cxt).Parse()
		if err != nil {
			t.Errorf("NewTag() = %v, want nil error.", err)
			return
		}
		if cxt.AlgMode() != tc.cxt {
			t.Errorf("Options.Mode = %v, want \"%v\".", cxt.AlgMode(), tc.cxt)
		}
		res := i.String()
		if res != tc.res {
			t.Errorf("Tag.String = \"%s\", want \"%s\".", res, tc.res)
		}
	}
}

/* Copyright 2017,2018 Spiegel
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
