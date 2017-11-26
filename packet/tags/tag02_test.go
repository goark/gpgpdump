package tags

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/options"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"

	openpgp "golang.org/x/crypto/openpgp/packet"
)

var (
	tag02Body1 = []byte{0x04, 0x01, 0x13, 0x08, 0x00, 0x06, 0x05, 0x02, 0x54, 0xc3, 0x08, 0xdf, 0x00, 0x0a, 0x09, 0x10, 0x31, 0xfb, 0xfd, 0xa9, 0x5f, 0xbb, 0xfa, 0x18, 0x36, 0x1f, 0x01, 0x00, 0xea, 0x1d, 0xa2, 0x14, 0x5b, 0x82, 0x06, 0xfd, 0xd5, 0xae, 0xc4, 0x9f, 0xd8, 0x14, 0x44, 0x41, 0xa4, 0xf5, 0x4f, 0x56, 0x69, 0xad, 0x9a, 0xb0, 0x44, 0xf3, 0xa3, 0x88, 0xb2, 0x60, 0xf4, 0x0c, 0x00, 0xfc, 0x0a, 0xd3, 0xc0, 0x23, 0xf3, 0xed, 0xcd, 0xaf, 0x9b, 0x19, 0x6f, 0xee, 0xc4, 0x65, 0x44, 0xb5, 0x08, 0xe8, 0x27, 0x6c, 0x3a, 0xa8, 0x6e, 0x3b, 0x52, 0x9f, 0x61, 0x7a, 0xea, 0xee, 0x27, 0x48}
)

const (
	tag02itemStr1 = `Signature Packet (tag 2) (94 bytes)
	Version: 4 (current)
	Signiture Type: Signature of a canonical text document (0x01)
	Public-key Algorithm: ECDSA public key algorithm (pub 19)
	Hash Algorithm: SHA256 (hash 8)
	Hashed Subpacket (6 bytes)
		Signature Creation Time (sub 2): 2015-01-24T11:52:15+09:00
	Unhashed Subpacket (10 bytes)
		Issuer (sub 16): 0x31fbfda95fbbfa18
	Hash left 2 bytes
		36 1f
	ECDSA r (256 bits)
	ECDSA s (252 bits)
`
)

func TestTag02(t *testing.T) {
	op := &openpgp.OpaquePacket{Tag: 2, Contents: tag02Body1}
	cxt := context.NewContext(options.New())
	i, err := NewTag(op, cxt).Parse()
	if err != nil {
		t.Errorf("NewTag() = %v, want nil error.", err)
		return
	}
	str := i.String()
	if str != tag02itemStr1 {
		t.Errorf("Tag.String = \"%s\", want \"%s\".", str, tag02itemStr1)
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
