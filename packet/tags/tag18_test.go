package tags

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/options"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"

	openpgp "golang.org/x/crypto/openpgp/packet"
)

var (
	tag18Body1 = []byte{0x01, 0x6a, 0xe6, 0x71, 0xca, 0xff, 0xf6, 0xb1, 0xff, 0x3f, 0x71, 0xc8, 0x77, 0x45, 0x88, 0x51, 0xff, 0xe3, 0xf2, 0xc3, 0x95, 0x57, 0xe7, 0x29, 0x80, 0xe8, 0xe5, 0x86, 0x7c, 0xea, 0x98, 0xf4, 0x04, 0xb3, 0x8a, 0xf8, 0x88, 0xc8, 0x91, 0xf7, 0x56, 0x7b, 0xcb, 0xad, 0x75, 0x40, 0x48, 0xd1, 0x5a, 0x3f, 0x3f, 0x2c, 0x1d, 0xe4, 0x36, 0xbb, 0xe9, 0xf7, 0x77, 0xb2, 0xb8, 0x2a, 0x44, 0x03, 0xbe, 0x78, 0xe2, 0x05, 0x3b, 0x44, 0xb6, 0xd8, 0x4e, 0x61, 0xa5, 0x43, 0x05, 0x76, 0x8a, 0x3c, 0x64}
)

const (
	tag18Result11 = `Sym. Encrypted Integrity Protected Data Packet (tag 18) (81 bytes)
	01 6a e6 71 ca ff f6 b1 ff 3f 71 c8 77 45 88 51 ff e3 f2 c3 95 57 e7 29 80 e8 e5 86 7c ea 98 f4 04 b3 8a f8 88 c8 91 f7 56 7b cb ad 75 40 48 d1 5a 3f 3f 2c 1d e4 36 bb e9 f7 77 b2 b8 2a 44 03 be 78 e2 05 3b 44 b6 d8 4e 61 a5 43 05 76 8a 3c 64
	Encrypted data (81 bytes)
		01 6a e6 71 ca ff f6 b1 ff 3f 71 c8 77 45 88 51 ff e3 f2 c3 95 57 e7 29 80 e8 e5 86 7c ea 98 f4 04 b3 8a f8 88 c8 91 f7 56 7b cb ad 75 40 48 d1 5a 3f 3f 2c 1d e4 36 bb e9 f7 77 b2 b8 2a 44 03 be 78 e2 05 3b 44 b6 d8 4e 61 a5 43 05 76 8a 3c 64
`
	tag18Result12 = `Sym. Encrypted Integrity Protected Data Packet (tag 18) (81 bytes)
	01 6a e6 71 ca ff f6 b1 ff 3f 71 c8 77 45 88 51 ff e3 f2 c3 95 57 e7 29 80 e8 e5 86 7c ea 98 f4 04 b3 8a f8 88 c8 91 f7 56 7b cb ad 75 40 48 d1 5a 3f 3f 2c 1d e4 36 bb e9 f7 77 b2 b8 2a 44 03 be 78 e2 05 3b 44 b6 d8 4e 61 a5 43 05 76 8a 3c 64
	Encrypted data (plain text + MDC SHA1(20 bytes); sym alg is specified in pub-key encrypted session key)
		01 6a e6 71 ca ff f6 b1 ff 3f 71 c8 77 45 88 51 ff e3 f2 c3 95 57 e7 29 80 e8 e5 86 7c ea 98 f4 04 b3 8a f8 88 c8 91 f7 56 7b cb ad 75 40 48 d1 5a 3f 3f 2c 1d e4 36 bb e9 f7 77 b2 b8 2a 44 03 be 78 e2 05 3b 44 b6 d8 4e 61 a5 43 05 76 8a 3c 64
`
	tag18Result13 = `Sym. Encrypted Integrity Protected Data Packet (tag 18) (81 bytes)
	01 6a e6 71 ca ff f6 b1 ff 3f 71 c8 77 45 88 51 ff e3 f2 c3 95 57 e7 29 80 e8 e5 86 7c ea 98 f4 04 b3 8a f8 88 c8 91 f7 56 7b cb ad 75 40 48 d1 5a 3f 3f 2c 1d e4 36 bb e9 f7 77 b2 b8 2a 44 03 be 78 e2 05 3b 44 b6 d8 4e 61 a5 43 05 76 8a 3c 64
	Encrypted data (plain text + MDC SHA1(20 bytes); sym alg is specified in sym-key encrypted session key)
		01 6a e6 71 ca ff f6 b1 ff 3f 71 c8 77 45 88 51 ff e3 f2 c3 95 57 e7 29 80 e8 e5 86 7c ea 98 f4 04 b3 8a f8 88 c8 91 f7 56 7b cb ad 75 40 48 d1 5a 3f 3f 2c 1d e4 36 bb e9 f7 77 b2 b8 2a 44 03 be 78 e2 05 3b 44 b6 d8 4e 61 a5 43 05 76 8a 3c 64
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
	}
	for _, tc := range testCases {
		op := &openpgp.OpaquePacket{Tag: tc.tag, Contents: tc.content}
		cxt := context.New(options.New(
			options.Set(options.DEBUG, true),
			options.Set(options.GDUMP, true),
			options.Set(options.INTEGER, true),
			options.Set(options.LITERAL, true),
			options.Set(options.MARKER, true),
			options.Set(options.PRIVATE, true),
			options.Set(options.UTC, true),
		))
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
