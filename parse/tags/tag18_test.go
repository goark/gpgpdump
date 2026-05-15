package tags

import (
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/values"
)

var (
	tag18Body1 = []byte{0x01, 0x6a, 0xe6, 0x71, 0xca, 0xff, 0xf6, 0xb1, 0xff, 0x3f, 0x71, 0xc8, 0x77, 0x45, 0x88, 0x51, 0xff, 0xe3, 0xf2, 0xc3, 0x95, 0x57, 0xe7, 0x29, 0x80, 0xe8, 0xe5, 0x86, 0x7c, 0xea, 0x98, 0xf4, 0x04, 0xb3, 0x8a, 0xf8, 0x88, 0xc8, 0x91, 0xf7, 0x56, 0x7b, 0xcb, 0xad, 0x75, 0x40, 0x48, 0xd1, 0x5a, 0x3f, 0x3f, 0x2c, 0x1d, 0xe4, 0x36, 0xbb, 0xe9, 0xf7, 0x77, 0xb2, 0xb8, 0x2a, 0x44, 0x03, 0xbe, 0x78, 0xe2, 0x05, 0x3b, 0x44, 0xb6, 0xd8, 0x4e, 0x61, 0xa5, 0x43, 0x05, 0x76, 0x8a, 0x3c, 0x64}
	tag18Body2 = []byte{0x02, 0x09, 0x02, 0x0e, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0xde, 0xad, 0xbe, 0xef}
)

const (
	tag18Result11 = `Sym. Encrypted Integrity Protected Data Packet (tag 18) (81 bytes)
	01 6a e6 71 ca ff f6 b1 ff 3f 71 c8 77 45 88 51 ff e3 f2 c3 95 57 e7 29 80 e8 e5 86 7c ea 98 f4 04 b3 8a f8 88 c8 91 f7 56 7b cb ad 75 40 48 d1 5a 3f 3f 2c 1d e4 36 bb e9 f7 77 b2 b8 2a 44 03 be 78 e2 05 3b 44 b6 d8 4e 61 a5 43 05 76 8a 3c 64
	Encrypted data (80 bytes)
		6a e6 71 ca ff f6 b1 ff 3f 71 c8 77 45 88 51 ff e3 f2 c3 95 57 e7 29 80 e8 e5 86 7c ea 98 f4 04 b3 8a f8 88 c8 91 f7 56 7b cb ad 75 40 48 d1 5a 3f 3f 2c 1d e4 36 bb e9 f7 77 b2 b8 2a 44 03 be 78 e2 05 3b 44 b6 d8 4e 61 a5 43 05 76 8a 3c 64
`
	tag18Result12 = `Sym. Encrypted Integrity Protected Data Packet (tag 18) (81 bytes)
	01 6a e6 71 ca ff f6 b1 ff 3f 71 c8 77 45 88 51 ff e3 f2 c3 95 57 e7 29 80 e8 e5 86 7c ea 98 f4 04 b3 8a f8 88 c8 91 f7 56 7b cb ad 75 40 48 d1 5a 3f 3f 2c 1d e4 36 bb e9 f7 77 b2 b8 2a 44 03 be 78 e2 05 3b 44 b6 d8 4e 61 a5 43 05 76 8a 3c 64
	Encrypted data (plain text + MDC SHA1(20 bytes); sym alg is specified in pub-key encrypted session key)
		6a e6 71 ca ff f6 b1 ff 3f 71 c8 77 45 88 51 ff e3 f2 c3 95 57 e7 29 80 e8 e5 86 7c ea 98 f4 04 b3 8a f8 88 c8 91 f7 56 7b cb ad 75 40 48 d1 5a 3f 3f 2c 1d e4 36 bb e9 f7 77 b2 b8 2a 44 03 be 78 e2 05 3b 44 b6 d8 4e 61 a5 43 05 76 8a 3c 64
`
	tag18Result13 = `Sym. Encrypted Integrity Protected Data Packet (tag 18) (81 bytes)
	01 6a e6 71 ca ff f6 b1 ff 3f 71 c8 77 45 88 51 ff e3 f2 c3 95 57 e7 29 80 e8 e5 86 7c ea 98 f4 04 b3 8a f8 88 c8 91 f7 56 7b cb ad 75 40 48 d1 5a 3f 3f 2c 1d e4 36 bb e9 f7 77 b2 b8 2a 44 03 be 78 e2 05 3b 44 b6 d8 4e 61 a5 43 05 76 8a 3c 64
	Encrypted data (plain text + MDC SHA1(20 bytes); sym alg is specified in sym-key encrypted session key)
		6a e6 71 ca ff f6 b1 ff 3f 71 c8 77 45 88 51 ff e3 f2 c3 95 57 e7 29 80 e8 e5 86 7c ea 98 f4 04 b3 8a f8 88 c8 91 f7 56 7b cb ad 75 40 48 d1 5a 3f 3f 2c 1d e4 36 bb e9 f7 77 b2 b8 2a 44 03 be 78 e2 05 3b 44 b6 d8 4e 61 a5 43 05 76 8a 3c 64
`
	tag18Result21 = `Sym. Encrypted Integrity Protected Data Packet (tag 18) (40 bytes)
	02 09 02 0e 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f de ad be ef
	Symmetric Algorithm: AES with 256-bit key (sym 9)
		09
	AEAD Algorithm: OCB mode <RFC7253> (aead 2)
		02
	Chunk size: 1048576
		0e
	salt
		00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
	Encrypted data (4 bytes)
		de ad be ef
`
)

func TestTag1(t *testing.T) {
	testCases := []struct {
		tag     uint8
		content []byte
		ktm     []byte
		cxt     context.SymAlgMode
		res     string
	}{
		{tag: 18, content: tag18Body1, ktm: nil, cxt: context.ModeNotSpecified, res: tag18Result11},
		{tag: 18, content: tag18Body1, ktm: nil, cxt: context.ModePubEnc, res: tag18Result12},
		{tag: 18, content: tag18Body1, ktm: nil, cxt: context.ModeSymEnc, res: tag18Result13},
		{tag: 18, content: tag18Body2, ktm: nil, cxt: context.ModeNotSpecified, res: tag18Result21},
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
		cxt.SymAlgMode = tc.cxt
		i, err := NewTag(op, cxt).Parse()
		if err != nil {
			t.Errorf("NewTag() = %v, want nil error.", err)
			return
		}
		if cxt.AlgMode() != context.ModeNotSpecified {
			t.Errorf("Options.Mode = %v, want \"%v\".", cxt.AlgMode(), tc.cxt)
		}
		res := i.String()
		if res != tc.res {
			t.Errorf("Tag.String = \"%s\", want \"%s\".", res, tc.res)
		}
	}
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
