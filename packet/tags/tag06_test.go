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
	tag06Body1 = []byte{0x04, 0x54, 0xc3, 0x01, 0xbf, 0x13, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x02, 0x03, 0x04, 0xa5, 0xd5, 0xbc, 0x76, 0x07, 0xdb, 0xb8, 0x8f, 0xb2, 0x21, 0x19, 0x11, 0xb0, 0xd0, 0x5a, 0x7e, 0xe9, 0x34, 0xdf, 0xa3, 0x8d, 0x8e, 0xf9, 0xb9, 0x7e, 0xb6, 0xd8, 0x63, 0x0a, 0xee, 0x92, 0xee, 0x0d, 0x74, 0xc7, 0xc0, 0x48, 0xf3, 0xb8, 0xd5, 0xaa, 0xa8, 0x73, 0xbd, 0xe7, 0x19, 0xb5, 0xda, 0xd8, 0xf6, 0x68, 0x05, 0x03, 0x15, 0x7d, 0x9a, 0x84, 0x43, 0x61, 0xca, 0xee, 0xdf, 0xd6, 0x0e}
)

const (
	tag06Result1 = `Public-Key Packet (tag 6) (82 bytes)
	04 54 c3 01 bf 13 08 2a 86 48 ce 3d 03 01 07 02 03 04 a5 d5 bc 76 07 db b8 8f b2 21 19 11 b0 d0 5a 7e e9 34 df a3 8d 8e f9 b9 7e b6 d8 63 0a ee 92 ee 0d 74 c7 c0 48 f3 b8 d5 aa a8 73 bd e7 19 b5 da d8 f6 68 05 03 15 7d 9a 84 43 61 ca ee df d6 0e
	Version: 4 (current)
		04
	Public key creation time: 2015-01-24T02:21:51Z
		54 c3 01 bf
	Public-key Algorithm: ECDSA public key algorithm (pub 19)
		13
	ECC Curve OID: nistp256 (256bits key size)
		2a 86 48 ce 3d 03 01 07
	ECDSA EC point (04 || X || Y) (515 bits)
		04 a5 d5 bc 76 07 db b8 8f b2 21 19 11 b0 d0 5a 7e e9 34 df a3 8d 8e f9 b9 7e b6 d8 63 0a ee 92 ee 0d 74 c7 c0 48 f3 b8 d5 aa a8 73 bd e7 19 b5 da d8 f6 68 05 03 15 7d 9a 84 43 61 ca ee df d6 0e
`
)

func TestTag06(t *testing.T) {
	testCases := []struct {
		tag     uint8
		content []byte
		ktm     []byte
		cxt     context.SymAlgMode
		res     string
	}{
		{tag: 6, content: tag06Body1, ktm: nil, cxt: context.ModeNotSpecified, res: tag06Result1},
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
