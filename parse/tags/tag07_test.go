package tags

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"

	"golang.org/x/crypto/openpgp/packet"
)

var (
	tag07Body1 = []byte{0x04, 0x5b, 0x1a, 0x4e, 0x1d, 0x12, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01, 0x01, 0x07, 0x40, 0x4a, 0xfb, 0x95, 0xcb, 0x33, 0xb2, 0xd9, 0xd5, 0x76, 0x19, 0x13, 0x39, 0x81, 0x9f, 0x64, 0x9b, 0x98, 0x43, 0x39, 0xc6, 0xa5, 0xfc, 0xf6, 0xfc, 0x9c, 0x9d, 0xba, 0x0d, 0xcc, 0x9a, 0x7d, 0x7d, 0x03, 0x01, 0x0a, 0x09, 0x00, 0x00, 0xff, 0x78, 0xd6, 0x1d, 0x85, 0xa4, 0xdd, 0x46, 0x38, 0x2f, 0xd6, 0xaa, 0x70, 0x7c, 0x09, 0x8f, 0xd5, 0x5d, 0x2b, 0x1a, 0xe3, 0x3f, 0x9b, 0x28, 0xc9, 0x4c, 0x75, 0x51, 0xec, 0xbf, 0xe1, 0xd5, 0x18, 0x10, 0xd1}
	tag07Body2 = []byte{0x05, 0x5c, 0x91, 0xf4, 0xe4, 0x12, 0x00, 0x00, 0x00, 0x32, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01, 0x01, 0x07, 0x40, 0xfa, 0x7c, 0xac, 0xaf, 0x39, 0xa5, 0xd9, 0x40, 0xb0, 0x78, 0x0a, 0xad, 0xa4, 0x3b, 0xa7, 0x71, 0x23, 0xe5, 0xbe, 0xb7, 0x01, 0x58, 0xa5, 0x34, 0xc9, 0xf5, 0x34, 0x62, 0xf6, 0x16, 0x58, 0x0a, 0x03, 0x01, 0x08, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0xff, 0x4e, 0x74, 0x03, 0xe9, 0xa6, 0x35, 0x35, 0x5b, 0x0a, 0x6a, 0x8c, 0x82, 0x2d, 0x93, 0x1a, 0xfe, 0x54, 0xf4, 0x11, 0x4f, 0xc6, 0x66, 0xfd, 0x18, 0xb0, 0xed, 0x4d, 0xc5, 0xea, 0xfd, 0xce, 0x88, 0x11, 0x47}
)

const (
	tag07Redult1 = `Secret-Subkey Packet (tag 7) (93 bytes)
	04 5b 1a 4e 1d 12 0a 2b 06 01 04 01 97 55 01 05 01 01 07 40 4a fb 95 cb 33 b2 d9 d5 76 19 13 39 81 9f 64 9b 98 43 39 c6 a5 fc f6 fc 9c 9d ba 0d cc 9a 7d 7d 03 01 0a 09 00 00 ff 78 d6 1d 85 a4 dd 46 38 2f d6 aa 70 7c 09 8f d5 5d 2b 1a e3 3f 9b 28 c9 4c 75 51 ec bf e1 d5 18 10 d1
	Version: 4 (current)
		04
	Public-Key
		Public key creation time: 2018-06-08T09:36:29Z
			5b 1a 4e 1d
		Public-key Algorithm: ECDH public key algorithm (pub 18)
			12
		ECC Curve OID: cv25519 (256bits key size)
			2b 06 01 04 01 97 55 01 05 01
		ECDH EC point (Native point format of the curve follows) (263 bits)
			40 4a fb 95 cb 33 b2 d9 d5 76 19 13 39 81 9f 64 9b 98 43 39 c6 a5 fc f6 fc 9c 9d ba 0d cc 9a 7d 7d
		KDF parameters (3 bytes)
			01 0a 09
			Hash Algorithm: SHA2-512 (hash 10)
				0a
			Symmetric Algorithm: AES with 256-bit key (sym 9)
				09
	Secret-Key (s2k usage 0; plain secret-key material)
		ECDH secret key (255 bits)
			78 d6 1d 85 a4 dd 46 38 2f d6 aa 70 7c 09 8f d5 5d 2b 1a e3 3f 9b 28 c9 4c 75 51 ec bf e1 d5 18
		2-octet checksum
			10 d1
`
	tag07Redult2 = `Secret-Subkey Packet (tag 7) (102 bytes)
	05 5c 91 f4 e4 12 00 00 00 32 0a 2b 06 01 04 01 97 55 01 05 01 01 07 40 fa 7c ac af 39 a5 d9 40 b0 78 0a ad a4 3b a7 71 23 e5 be b7 01 58 a5 34 c9 f5 34 62 f6 16 58 0a 03 01 08 07 00 00 00 00 00 22 00 ff 4e 74 03 e9 a6 35 35 5b 0a 6a 8c 82 2d 93 1a fe 54 f4 11 4f c6 66 fd 18 b0 ed 4d c5 ea fd ce 88 11 47
	Version: 5 (draft)
		05
	Public-Key
		Public key creation time: 2019-03-20T08:08:04Z
			5c 91 f4 e4
		Public-key Algorithm: ECDH public key algorithm (pub 18)
			12
		ECC Curve OID: cv25519 (256bits key size)
			2b 06 01 04 01 97 55 01 05 01
		ECDH EC point (Native point format of the curve follows) (263 bits)
			40 fa 7c ac af 39 a5 d9 40 b0 78 0a ad a4 3b a7 71 23 e5 be b7 01 58 a5 34 c9 f5 34 62 f6 16 58 0a
		KDF parameters (3 bytes)
			01 08 07
			Hash Algorithm: SHA2-256 (hash 8)
				08
			Symmetric Algorithm: AES with 128-bit key (sym 7)
				07
	Secret-Key (s2k usage 0; plain secret-key material)
		ECDH secret key (255 bits)
			4e 74 03 e9 a6 35 35 5b 0a 6a 8c 82 2d 93 1a fe 54 f4 11 4f c6 66 fd 18 b0 ed 4d c5 ea fd ce 88
		2-octet checksum
			11 47
`
)

func TestTag07(t *testing.T) {
	testCases := []struct {
		tag     uint8
		content []byte
		ktm     []byte
		cxt     context.SymAlgMode
		res     string
	}{
		{tag: 7, content: tag07Body1, ktm: nil, cxt: context.ModeNotSpecified, res: tag07Redult1},
		{tag: 7, content: tag07Body2, ktm: nil, cxt: context.ModeNotSpecified, res: tag07Redult2},
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

/* Copyright 2018,2019 Spiegel
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
