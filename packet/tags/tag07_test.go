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
	tag07Body1 = []byte{0x04, 0x5b, 0x1a, 0x4e, 0x1d, 0x12, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01, 0x01, 0x07, 0x40, 0x4a, 0xfb, 0x95, 0xcb, 0x33, 0xb2, 0xd9, 0xd5, 0x76, 0x19, 0x13, 0x39, 0x81, 0x9f, 0x64, 0x9b, 0x98, 0x43, 0x39, 0xc6, 0xa5, 0xfc, 0xf6, 0xfc, 0x9c, 0x9d, 0xba, 0x0d, 0xcc, 0x9a, 0x7d, 0x7d, 0x03, 0x01, 0x0a, 0x09, 0x00, 0x00, 0xff, 0x78, 0xd6, 0x1d, 0x85, 0xa4, 0xdd, 0x46, 0x38, 0x2f, 0xd6, 0xaa, 0x70, 0x7c, 0x09, 0x8f, 0xd5, 0x5d, 0x2b, 0x1a, 0xe3, 0x3f, 0x9b, 0x28, 0xc9, 0x4c, 0x75, 0x51, 0xec, 0xbf, 0xe1, 0xd5, 0x18, 0x10, 0xd1}
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
		ECDH EC point (04 || X || Y) (263 bits)
			40 4a fb 95 cb 33 b2 d9 d5 76 19 13 39 81 9f 64 9b 98 43 39 c6 a5 fc f6 fc 9c 9d ba 0d cc 9a 7d 7d
		KDF parameters (3 bytes)
			01 0a 09
			Hash Algorithm: SHA2-512 (hash 10)
				0a
			Symmetric Algorithm: AES with 256-bit key (sym 9)
				09
	Secret-Key (the secret-key data is not encrypted.)
		ECDH EC point (04 || X || Y) (255 bits)
			78 d6 1d 85 a4 dd 46 38 2f d6 aa 70 7c 09 8f d5 5d 2b 1a e3 3f 9b 28 c9 4c 75 51 ec bf e1 d5 18
		Checksum
			10 d1
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
	}
	for _, tc := range testCases {
		op := &openpgp.OpaquePacket{Tag: tc.tag, Contents: tc.content}
		cxt := context.NewContext(options.New(
			options.Set(options.DebugOpt, true),
			options.Set(options.IntegerOpt, true),
			options.Set(options.MarkerOpt, true),
			options.Set(options.LiteralOpt, true),
			options.Set(options.PrivateOpt, true),
			options.Set(options.UTCOpt, true),
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

/* Copyright 2018 Spiegel
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
