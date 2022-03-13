package pubkey

import (
	"testing"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

var (
	secPlain01  = []byte{0x07, 0xfb, 0x07, 0x33, 0xd7, 0xc9, 0x9a, 0xd6, 0x6a, 0xb8, 0xc8, 0xa1, 0xa4, 0x79, 0xae, 0x35, 0x20, 0xb2, 0x99, 0x5d, 0xd3, 0x6b, 0x2f, 0x58, 0xc8, 0xa4, 0xd8, 0x92, 0x0b, 0xca, 0x9e, 0x50, 0x5c, 0x92, 0xe8, 0xd3, 0xf0, 0xbd, 0x1d, 0x34, 0xf4, 0x68, 0x09, 0xcf, 0x7d, 0xb4, 0x66, 0x7c, 0x48, 0x08, 0xdb, 0xa3, 0x84, 0x5d, 0x4b, 0x2a, 0xe5, 0x97, 0x9e, 0x8a, 0xdb, 0xad, 0x50, 0xcc, 0x14, 0xec, 0xde, 0xc3, 0xce, 0xc2, 0xa0, 0xd4, 0x1d, 0x6c, 0x42, 0xf8, 0x69, 0xb9, 0xc6, 0x25, 0x21, 0x11, 0xa8, 0xb8, 0x27, 0x37, 0xb6, 0x6e, 0x10, 0x8c, 0xcf, 0x70, 0x7b, 0xfd, 0x57, 0xa5, 0x36, 0xba, 0x18, 0x0d, 0xc6, 0xb8, 0x5a, 0xb3, 0x26, 0x5d, 0xec, 0x36, 0x79, 0xe3, 0x13, 0x59, 0x3e, 0x37, 0xcd, 0xcb, 0x77, 0x70, 0x9d, 0x8a, 0xc6, 0xf7, 0x23, 0x97, 0x3b, 0xbf, 0xdb, 0xc4, 0x86, 0x84, 0x03, 0x81, 0x7f, 0xf0, 0x54, 0xff, 0x92, 0x7d, 0x9b, 0x88, 0x9b, 0x9f, 0x28, 0x8b, 0xcd, 0x85, 0x76, 0xa6, 0xdb, 0x52, 0x9c, 0x8f, 0x33, 0x9e, 0x34, 0x79, 0x6f, 0xdd, 0x99, 0x2e, 0x3d, 0xca, 0x76, 0x74, 0x09, 0x71, 0x67, 0x7e, 0xbc, 0x51, 0x9f, 0x6b, 0x25, 0x48, 0x68, 0x7d, 0x3d, 0xa8, 0x8b, 0xfe, 0x92, 0x42, 0x9f, 0xc4, 0x93, 0xc6, 0x76, 0xc2, 0xb7, 0xd9, 0xc2, 0x75, 0xd1, 0xad, 0xe4, 0x28, 0x36, 0x26, 0x15, 0xb8, 0xa1, 0x4d, 0x4d, 0xab, 0xe5, 0xf1, 0x80, 0x41, 0x82, 0x56, 0xe4, 0x9c, 0x74, 0x2e, 0xee, 0xbf, 0xba, 0x8b, 0xee, 0xb2, 0x05, 0xa2, 0xb9, 0x08, 0x2f, 0x8f, 0xfe, 0xae, 0x64, 0x8e, 0x03, 0x6d, 0xc4, 0x79, 0x7b, 0xe3, 0xe1, 0x33, 0x5b, 0x1c, 0x71, 0x0e, 0xce, 0x6d, 0xa2, 0x92, 0x41, 0xb6, 0xde, 0xfd, 0x1a, 0x5d, 0x48, 0x3c, 0x19, 0x14, 0x58, 0x49, 0x04, 0x00, 0xb6, 0x95, 0xff, 0x19, 0x0d, 0x79, 0xd7, 0x72, 0xd0, 0x51, 0xe4, 0x87, 0x08, 0xff, 0xce, 0x03, 0x36, 0x9b, 0x05, 0xb5, 0x2b, 0xf4, 0x63, 0xaa, 0xf0, 0x78, 0xe0, 0x7d, 0xc3, 0xd0, 0xc2, 0xe5, 0x61, 0x88, 0x36, 0x22, 0x30, 0x6d, 0xe4, 0x9b, 0xf9, 0x80, 0x70, 0xd8, 0xd2, 0xa4, 0xf4, 0x8f, 0xd7, 0x3b, 0xe5, 0x69, 0xef, 0xe9, 0x61, 0x50, 0x8d, 0x36, 0xef, 0x77, 0x84, 0xff, 0xa9, 0x92, 0x83, 0xb1, 0xd8, 0x65, 0x4f, 0x4b, 0x62, 0xb4, 0x34, 0x03, 0xc4, 0x4b, 0x81, 0xba, 0xa3, 0x37, 0xe2, 0xb8, 0x06, 0xcf, 0x40, 0x8b, 0x7a, 0x4b, 0x03, 0xd7, 0xfa, 0xac, 0xbc, 0x73, 0x60, 0x8d, 0x1c, 0x32, 0xe5, 0x58, 0x41, 0x86, 0x7e, 0x5e, 0x1f, 0x0e, 0x3d, 0x53, 0x42, 0xf0, 0x2f, 0x7e, 0x28, 0x9a, 0x76, 0x40, 0xd8, 0x6a, 0x64, 0x76, 0x57, 0x69, 0xfe, 0x64, 0x68, 0x31, 0x70, 0x79, 0x04, 0x00, 0xc2, 0xd8, 0xc8, 0x85, 0xb0, 0x0a, 0x1b, 0xea, 0x8e, 0x06, 0xa7, 0x1a, 0x38, 0x4d, 0xb4, 0x6f, 0x2e, 0x90, 0x20, 0x7d, 0xfb, 0xf2, 0x4f, 0xd5, 0x5b, 0xbf, 0x7c, 0x81, 0x15, 0x3c, 0x4b, 0xfa, 0x21, 0xb0, 0xc3, 0x46, 0xb1, 0x4f, 0x25, 0xe8, 0xaf, 0x2e, 0x0d, 0xe0, 0xeb, 0xb1, 0x96, 0x06, 0xa3, 0x0c, 0xb7, 0x35, 0xaa, 0xbd, 0x6d, 0x55, 0x7f, 0xc4, 0x07, 0xd0, 0x1d, 0x1f, 0x67, 0x95, 0x73, 0x86, 0xba, 0x67, 0xcc, 0xad, 0x6a, 0xf3, 0x97, 0xa1, 0xf6, 0x65, 0xfa, 0xaa, 0xeb, 0x24, 0xd9, 0xb2, 0x30, 0x63, 0xa3, 0xdc, 0x9e, 0x2f, 0x89, 0xf6, 0xe9, 0x52, 0x20, 0x7f, 0x72, 0x82, 0x9a, 0x9f, 0xa0, 0x1d, 0xf6, 0x18, 0xe1, 0xfb, 0x48, 0xab, 0xf3, 0x46, 0x34, 0x4b, 0x4e, 0x8a, 0x31, 0x48, 0xd3, 0x3d, 0x74, 0x31, 0x30, 0xf8, 0x63, 0x7c, 0x47, 0xf7, 0x3c, 0x92, 0xd0, 0x23, 0x03, 0xfe, 0x2a, 0xe3, 0xab, 0x31, 0x74, 0x13, 0x51, 0xc4, 0xc0, 0x5e, 0xb5, 0xec, 0xac, 0x3c, 0xcc, 0xc6, 0xc7, 0x6a, 0x8c, 0xe3, 0xb1, 0x81, 0x06, 0xc5, 0x9b, 0xd2, 0x26, 0xdc, 0x0c, 0xde, 0x67, 0x6e, 0xcb, 0x10, 0x0d, 0x01, 0x23, 0x91, 0x2c, 0x68, 0x90, 0x71, 0x9a, 0x3d, 0xb7, 0xc4, 0xd2, 0x64, 0x18, 0xb5, 0x61, 0xd1, 0x77, 0x0a, 0xd5, 0x4e, 0xda, 0xcb, 0x57, 0x65, 0x8f, 0xb7, 0xac, 0x3d, 0x5a, 0x41, 0x64, 0x87, 0xc5, 0xb8, 0x4d, 0x86, 0x11, 0x9d, 0xaf, 0xc0, 0x97, 0x67, 0x9e, 0xd6, 0xab, 0x7e, 0xb7, 0xc2, 0x2e, 0x1e, 0xa7, 0x15, 0x63, 0xe7, 0x2f, 0x83, 0x13, 0xcf, 0x96, 0xd9, 0x14, 0xed, 0x1d, 0x45, 0xa4, 0x46, 0x83, 0x0d, 0x47, 0xb3, 0x1a, 0xb4, 0xef, 0x45, 0xbb, 0xa7, 0xf3, 0xae, 0x12, 0x6f, 0x40, 0xaa, 0xfd, 0xd2, 0x68, 0x80, 0xc8, 0xdb, 0x60, 0x89, 0xb6, 0x86, 0x7f, 0x2a}
	secPlain22  = []byte{0x00, 0xff, 0x50, 0x5e, 0xcc, 0x13, 0x31, 0x23, 0x59, 0x49, 0xc2, 0xcc, 0x48, 0x1d, 0x7c, 0xe8, 0x39, 0x85, 0xac, 0x36, 0x2f, 0x76, 0xff, 0x5a, 0xe5, 0xd6, 0x09, 0x68, 0xc6, 0xe7, 0xde, 0xcb, 0x00, 0x5c, 0x10, 0x55}
	secPlain22b = []byte{0x01, 0x00, 0x87, 0x67, 0x54, 0xa7, 0x49, 0x49, 0x96, 0xab, 0x11, 0x2c, 0xa0, 0x8e, 0x9f, 0x69, 0xc2, 0x15, 0x65, 0x0b, 0xba, 0x9a, 0x98, 0x77, 0x70, 0x11, 0x73, 0xcd, 0x3b, 0xdc, 0x9b, 0x99, 0x40, 0x36, 0x0e, 0x5c}
)

const (
	secPlainResult01 = `
	RSA secret exponent d (2043 bits)
		07 33 d7 c9 9a d6 6a b8 c8 a1 a4 79 ae 35 20 b2 99 5d d3 6b 2f 58 c8 a4 d8 92 0b ca 9e 50 5c 92 e8 d3 f0 bd 1d 34 f4 68 09 cf 7d b4 66 7c 48 08 db a3 84 5d 4b 2a e5 97 9e 8a db ad 50 cc 14 ec de c3 ce c2 a0 d4 1d 6c 42 f8 69 b9 c6 25 21 11 a8 b8 27 37 b6 6e 10 8c cf 70 7b fd 57 a5 36 ba 18 0d c6 b8 5a b3 26 5d ec 36 79 e3 13 59 3e 37 cd cb 77 70 9d 8a c6 f7 23 97 3b bf db c4 86 84 03 81 7f f0 54 ff 92 7d 9b 88 9b 9f 28 8b cd 85 76 a6 db 52 9c 8f 33 9e 34 79 6f dd 99 2e 3d ca 76 74 09 71 67 7e bc 51 9f 6b 25 48 68 7d 3d a8 8b fe 92 42 9f c4 93 c6 76 c2 b7 d9 c2 75 d1 ad e4 28 36 26 15 b8 a1 4d 4d ab e5 f1 80 41 82 56 e4 9c 74 2e ee bf ba 8b ee b2 05 a2 b9 08 2f 8f fe ae 64 8e 03 6d c4 79 7b e3 e1 33 5b 1c 71 0e ce 6d a2 92 41 b6 de fd 1a 5d 48 3c 19 14 58 49
	RSA secret prime value p (1024 bits)
		b6 95 ff 19 0d 79 d7 72 d0 51 e4 87 08 ff ce 03 36 9b 05 b5 2b f4 63 aa f0 78 e0 7d c3 d0 c2 e5 61 88 36 22 30 6d e4 9b f9 80 70 d8 d2 a4 f4 8f d7 3b e5 69 ef e9 61 50 8d 36 ef 77 84 ff a9 92 83 b1 d8 65 4f 4b 62 b4 34 03 c4 4b 81 ba a3 37 e2 b8 06 cf 40 8b 7a 4b 03 d7 fa ac bc 73 60 8d 1c 32 e5 58 41 86 7e 5e 1f 0e 3d 53 42 f0 2f 7e 28 9a 76 40 d8 6a 64 76 57 69 fe 64 68 31 70 79
	RSA secret prime value q (p < q) (1024 bits)
		c2 d8 c8 85 b0 0a 1b ea 8e 06 a7 1a 38 4d b4 6f 2e 90 20 7d fb f2 4f d5 5b bf 7c 81 15 3c 4b fa 21 b0 c3 46 b1 4f 25 e8 af 2e 0d e0 eb b1 96 06 a3 0c b7 35 aa bd 6d 55 7f c4 07 d0 1d 1f 67 95 73 86 ba 67 cc ad 6a f3 97 a1 f6 65 fa aa eb 24 d9 b2 30 63 a3 dc 9e 2f 89 f6 e9 52 20 7f 72 82 9a 9f a0 1d f6 18 e1 fb 48 ab f3 46 34 4b 4e 8a 31 48 d3 3d 74 31 30 f8 63 7c 47 f7 3c 92 d0 23
	RSA u, the multiplicative inverse of p, mod q (1022 bits)
		2a e3 ab 31 74 13 51 c4 c0 5e b5 ec ac 3c cc c6 c7 6a 8c e3 b1 81 06 c5 9b d2 26 dc 0c de 67 6e cb 10 0d 01 23 91 2c 68 90 71 9a 3d b7 c4 d2 64 18 b5 61 d1 77 0a d5 4e da cb 57 65 8f b7 ac 3d 5a 41 64 87 c5 b8 4d 86 11 9d af c0 97 67 9e d6 ab 7e b7 c2 2e 1e a7 15 63 e7 2f 83 13 cf 96 d9 14 ed 1d 45 a4 46 83 0d 47 b3 1a b4 ef 45 bb a7 f3 ae 12 6f 40 aa fd d2 68 80 c8 db 60 89 b6 86
`
	secPlainResult22 = `
	EdDSA secret key (255 bits)
		50 5e cc 13 31 23 59 49 c2 cc 48 1d 7c e8 39 85 ac 36 2f 76 ff 5a e5 d6 09 68 c6 e7 de cb 00 5c
`
	secPlainResult22b = `
	EdDSA secret key (256 bits)
		87 67 54 a7 49 49 96 ab 11 2c a0 8e 9f 69 c2 15 65 0b ba 9a 98 77 70 11 73 cd 3b dc 9b 99 40 36
`
)

func TestSeckeyPlain(t *testing.T) {
	testCases := []struct {
		pubID   uint8
		content []byte
		res     string
	}{
		{pubID: 1, content: secPlain01, res: secPlainResult01},
		{pubID: 22, content: secPlain22, res: secPlainResult22},
		{pubID: 22, content: secPlain22b, res: secPlainResult22b},
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
		if err := New(cxt, values.PubID(tc.pubID), reader.New(tc.content)).ParseSecPlain(parent); err != nil {
			t.Errorf("Parse() = %+v, want nil error.", err)
		}
		str := parent.String()
		if str != tc.res {
			t.Errorf("Parse() = \"%v\", want \"%v\".", str, tc.res)
		}
	}
}

/* Copyright 2018-2020 Spiegel
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
