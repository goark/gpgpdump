package tags

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/options"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"

	openpgp "golang.org/x/crypto/openpgp/packet"
)

var (
	tag08Body1 = []byte{0x01, 0x9b, 0xc0, 0xcb, 0xcc, 0xc0, 0x21, 0xb8, 0xe5, 0x96, 0xf5, 0xba, 0x3a, 0x85, 0x1d, 0x32, 0x8c, 0xa7, 0x85, 0x93, 0x18, 0xa2, 0x24, 0x79, 0x9f, 0x78, 0xa4, 0xe6, 0xe4, 0xe4, 0x2b, 0x94, 0xe7, 0x17, 0xe5, 0xa4, 0xf0, 0x72, 0x75, 0x94, 0xb2, 0x30, 0x08, 0x72, 0x30, 0xc8, 0x8a, 0x29, 0xb2, 0x48, 0x07, 0x31, 0xdd, 0xf6, 0xb2, 0x3b, 0x5e, 0xf6, 0xf1, 0xc1, 0x5a, 0x09, 0x98, 0x26, 0x56, 0x26, 0x90, 0x0e, 0x06, 0x2e, 0x4e, 0x01, 0x98, 0x48, 0xb1, 0x0d, 0x23, 0x43, 0xcb, 0xfb, 0x77, 0xeb, 0x94, 0x32, 0xf5, 0xd6, 0x1b, 0x6f, 0x6e, 0x7d, 0xf8, 0x6e, 0x55, 0xac, 0x7e, 0xd5, 0x95, 0x75, 0x8b, 0x27, 0x5d, 0x7e, 0x51, 0x7c, 0x65, 0x03, 0x83, 0xdd, 0x49, 0xed, 0x86, 0xef, 0x0c, 0xff, 0x6b, 0xce, 0xec, 0xbc, 0xc4, 0xe6, 0xb1, 0xd9, 0x32, 0x62, 0xf6, 0x8a, 0x99, 0x47, 0x0f, 0x05, 0x27, 0xed, 0xed, 0x17, 0xf3, 0x2c, 0x7e, 0x90, 0xfa, 0x6f, 0xd9, 0x77, 0x09, 0xa9, 0x8a, 0xff, 0xa9, 0xcf, 0x00}
)

const (
	tag08itemStr1 = `Compressed Data Packet (tag 8) (149 bytes)
	01 9b c0 cb cc c0 21 b8 e5 96 f5 ba 3a 85 1d 32 8c a7 85 93 18 a2 24 79 9f 78 a4 e6 e4 e4 2b 94 e7 17 e5 a4 f0 72 75 94 b2 30 08 72 30 c8 8a 29 b2 48 07 31 dd f6 b2 3b 5e f6 f1 c1 5a 09 98 26 56 26 90 0e 06 2e 4e 01 98 48 b1 0d 23 43 cb fb 77 eb 94 32 f5 d6 1b 6f 6e 7d f8 6e 55 ac 7e d5 95 75 8b 27 5d 7e 51 7c 65 03 83 dd 49 ed 86 ef 0c ff 6b ce ec bc c4 e6 b1 d9 32 62 f6 8a 99 47 0f 05 27 ed ed 17 f3 2c 7e 90 fa 6f d9 77 09 a9 8a ff a9 cf 00
	Compression Algorithm: ZIP <RFC1951> (comp 1)
		01
	Compressed data (148 bytes)
		9b c0 cb cc c0 21 b8 e5 96 f5 ba 3a 85 1d 32 8c a7 85 93 18 a2 24 79 9f 78 a4 e6 e4 e4 2b 94 e7 17 e5 a4 f0 72 75 94 b2 30 08 72 30 c8 8a 29 b2 48 07 31 dd f6 b2 3b 5e f6 f1 c1 5a 09 98 26 56 26 90 0e 06 2e 4e 01 98 48 b1 0d 23 43 cb fb 77 eb 94 32 f5 d6 1b 6f 6e 7d f8 6e 55 ac 7e d5 95 75 8b 27 5d 7e 51 7c 65 03 83 dd 49 ed 86 ef 0c ff 6b ce ec bc c4 e6 b1 d9 32 62 f6 8a 99 47 0f 05 27 ed ed 17 f3 2c 7e 90 fa 6f d9 77 09 a9 8a ff a9 cf 00
`
)

var (
	tag08Name1           = "Compressed Data Packet (tag 8)"
	tag08Name1Item0Name  = "Compression Algorithm"
	tag08Name1Item0Value = "ZIP <RFC1951> (comp 1)"
	tag08Name1Item1Name  = "Compressed data"
)

func TestTag08(t *testing.T) {
	op := &openpgp.OpaquePacket{Tag: 8, Contents: tag08Body1}
	opts := options.New(
		options.Set(options.DebugOpt, true),
		options.Set(options.UTCOpt, true),
	)
	cxt := context.NewContext(opts)
	i, err := NewTag(op, cxt).Parse()
	if err != nil {
		t.Errorf("NewTag() = %v, want nil error.", err)
		return
	}
	str := i.String()
	if str != tag08itemStr1 {
		t.Errorf("Tag.String = \"%s\", want \"%s\".", str, tag08itemStr1)
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
