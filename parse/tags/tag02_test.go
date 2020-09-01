package tags

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
	"golang.org/x/crypto/openpgp/packet"
)

var (
	tag02Body1 = []byte{0x04, 0x01, 0x13, 0x08, 0x00, 0x06, 0x05, 0x02, 0x54, 0xc3, 0x08, 0xdf, 0x00, 0x0a, 0x09, 0x10, 0x31, 0xfb, 0xfd, 0xa9, 0x5f, 0xbb, 0xfa, 0x18, 0x36, 0x1f, 0x01, 0x00, 0xea, 0x1d, 0xa2, 0x14, 0x5b, 0x82, 0x06, 0xfd, 0xd5, 0xae, 0xc4, 0x9f, 0xd8, 0x14, 0x44, 0x41, 0xa4, 0xf5, 0x4f, 0x56, 0x69, 0xad, 0x9a, 0xb0, 0x44, 0xf3, 0xa3, 0x88, 0xb2, 0x60, 0xf4, 0x0c, 0x00, 0xfc, 0x0a, 0xd3, 0xc0, 0x23, 0xf3, 0xed, 0xcd, 0xaf, 0x9b, 0x19, 0x6f, 0xee, 0xc4, 0x65, 0x44, 0xb5, 0x08, 0xe8, 0x27, 0x6c, 0x3a, 0xa8, 0x6e, 0x3b, 0x52, 0x9f, 0x61, 0x7a, 0xea, 0xee, 0x27, 0x48}
	tag02Body2 = []byte{0x04, 0x00, 0x11, 0x08, 0x00, 0x1d, 0x16, 0x21, 0x04, 0x1b, 0x52, 0x02, 0xdb, 0x4a, 0x3e, 0xc7, 0x76, 0xf1, 0xe0, 0xad, 0x18, 0xb4, 0xda, 0x3b, 0xae, 0x7e, 0x20, 0xb8, 0x1c, 0x05, 0x02, 0x5a, 0x19, 0x0d, 0xe4, 0x00, 0x0a, 0x09, 0x10, 0xb4, 0xda, 0x3b, 0xae, 0x7e, 0x20, 0xb8, 0x1c, 0x73, 0x3c, 0x01, 0x00, 0x84, 0xef, 0xee, 0xae, 0x22, 0x69, 0x2e, 0xaf, 0x33, 0xb3, 0x85, 0xe1, 0xee, 0xaa, 0x5d, 0x2f, 0x7a, 0xd4, 0xae, 0xa3, 0x92, 0xd3, 0xe8, 0x73, 0xd4, 0xb0, 0x00, 0x3e, 0xc9, 0x2b, 0x80, 0xf7, 0x00, 0xff, 0x7c, 0xcc, 0xb9, 0xd2, 0x06, 0x48, 0xb3, 0x39, 0x58, 0x9b, 0xa8, 0x99, 0xc5, 0xc2, 0x53, 0x62, 0xbd, 0x8f, 0x16, 0x49, 0x73, 0xe0, 0x65, 0xfe, 0xa6, 0xf7, 0x18, 0x1a, 0x78, 0xff, 0x65, 0xe6}
	tag02Body3 = []byte{0x04, 0x18, 0x13, 0x08, 0x00, 0x0f, 0x05, 0x02, 0x54, 0xc3, 0x01, 0xbf, 0x02, 0x1b, 0x0c, 0x05, 0x09, 0x00, 0x09, 0x3a, 0x80, 0x00, 0x0a, 0x09, 0x10, 0x31, 0xfb, 0xfd, 0xa9, 0x5f, 0xbb, 0xfa, 0x18, 0xc6, 0x27, 0x01, 0x00, 0xc0, 0x2f, 0x76, 0x5a, 0x10, 0x6d, 0x1d, 0x22, 0x1e, 0x62, 0xc1, 0x9b, 0xbc, 0x62, 0xd1, 0x06, 0x4a, 0xf1, 0x3a, 0x47, 0x5a, 0xe9, 0x0b, 0xf1, 0x39, 0x6c, 0xe3, 0x67, 0xa0, 0x96, 0x3c, 0xd2, 0x01, 0x00, 0x8c, 0x59, 0x1c, 0x3a, 0x85, 0x0e, 0x1e, 0xd3, 0x98, 0x45, 0x13, 0x4d, 0x30, 0xe2, 0xb9, 0xa4, 0x15, 0x0e, 0x1b, 0x6d, 0x66, 0x1a, 0xa7, 0xe7, 0xd5, 0xe2, 0x51, 0x07, 0x95, 0x60, 0x87, 0x91}
	tag02Body4 = []byte{0x03, 0x05, 0x00, 0x36, 0x5e, 0xba, 0x44, 0x0f, 0x64, 0x8a, 0x1c, 0x9e, 0x4f, 0x74, 0x4d, 0x01, 0x01, 0x66, 0x36, 0x04, 0x00, 0x8f, 0x8c, 0x6b, 0x45, 0xa7, 0x65, 0xbd, 0x37, 0xf6, 0x76, 0x58, 0x85, 0x7c, 0x39, 0x66, 0x7a, 0xc5, 0xc1, 0x48, 0xf3, 0xb8, 0x85, 0x69, 0x7f, 0x22, 0x54, 0x71, 0x50, 0x0e, 0x97, 0xb2, 0x51, 0x77, 0x53, 0xa2, 0x22, 0xd4, 0x46, 0xec, 0x0c, 0x50, 0xbe, 0xee, 0xe6, 0xb0, 0xc2, 0x76, 0x08, 0xf0, 0x6b, 0x0e, 0x6c, 0xfc, 0xe6, 0xef, 0xcd, 0x10, 0x3d, 0x10, 0xfd, 0xb3, 0x87, 0x40, 0x20, 0x55, 0x6c, 0x06, 0xae, 0x41, 0xc5, 0x7c, 0x0d, 0x17, 0x75, 0x44, 0x32, 0x7d, 0x08, 0x41, 0x45, 0x95, 0xda, 0xd6, 0x57, 0x74, 0x58, 0x38, 0x72, 0x6e, 0xf7, 0x1f, 0x63, 0xce, 0xd8, 0x00, 0x1b, 0x25, 0x37, 0x23, 0xb2, 0x56, 0x1a, 0x02, 0x9a, 0xee, 0x5a, 0x57, 0xf7, 0xa3, 0xab, 0x2d, 0x89, 0x20, 0x85, 0x1c, 0xc5, 0xc0, 0xec, 0x64, 0xe9, 0x2f, 0x0b, 0xf5, 0x4b, 0x5f, 0x2b, 0x65, 0x39}
	tag02Body5 = []byte{0x04, 0x13, 0x01, 0x08, 0x00, 0x1e, 0x05, 0x02, 0x5a, 0xfa, 0x85, 0x65, 0x02, 0x9b, 0x2f, 0x05, 0x8b, 0x09, 0x08, 0x07, 0x02, 0x06, 0x95, 0x0a, 0x09, 0x08, 0x0b, 0x02, 0x04, 0x96, 0x02, 0x03, 0x01, 0x02, 0x9e, 0x01, 0x00, 0x0a, 0x09, 0x10, 0x8e, 0x3d, 0xba, 0x0e, 0xc4, 0xdc, 0xc3, 0xb7, 0xef, 0x56, 0x07, 0xff, 0x63, 0xcf, 0x00, 0x07, 0x32, 0xd7, 0x4c, 0x58, 0x0b, 0xa3, 0x81, 0x0e, 0xd7, 0x3e, 0xde, 0x04, 0xd4, 0xf8, 0x63, 0x87, 0x49, 0xf3, 0x3c, 0x8a, 0x36, 0x47, 0x30, 0x25, 0x15, 0x5b, 0x3a, 0xea, 0x75, 0x95, 0x53, 0x70, 0x31, 0xbe, 0xb9, 0x23, 0x2a, 0xa7, 0xc5, 0xb4, 0xd7, 0x56, 0xcb, 0x00, 0x1c, 0xc6, 0x03, 0xf4, 0x49, 0x87, 0xcd, 0x07, 0xd5, 0xd4, 0x1f, 0xc1, 0x95, 0xc1, 0xf7, 0x0e, 0x16, 0x27, 0x54, 0xda, 0x4e, 0xa0, 0xea, 0xde, 0x5b, 0xdd, 0xeb, 0x4d, 0x17, 0x19, 0x4b, 0x61, 0x30, 0x52, 0xd0, 0x02, 0x50, 0x16, 0x5a, 0xb5, 0xcf, 0xa7, 0x64, 0x2c, 0x89, 0xff, 0x67, 0x12, 0x9b, 0xce, 0xb6, 0xba, 0x92, 0xa4, 0x61, 0x25, 0x96, 0x06, 0x14, 0x23, 0xed, 0x6d, 0x30, 0x8f, 0xe5, 0x26, 0x9c, 0x66, 0x5b, 0x6f, 0x34, 0x05, 0x66, 0x13, 0xb7, 0xcd, 0x90, 0xbc, 0x38, 0x84, 0xaf, 0x5f, 0x8f, 0x20, 0x07, 0xd0, 0xe5, 0xbd, 0x17, 0x23, 0x4f, 0x2a, 0x5d, 0x37, 0x17, 0xd8, 0xf8, 0xb4, 0x2f, 0xe6, 0xbe, 0x28, 0x79, 0xbc, 0x00, 0x05, 0x18, 0xac, 0xab, 0xd6, 0xea, 0x9d, 0xf4, 0x6c, 0x1a, 0xdd, 0xc9, 0x6a, 0x87, 0x9e, 0x19, 0x2f, 0xff, 0x12, 0xaa, 0x69, 0x49, 0x3e, 0x93, 0xee, 0x78, 0x8c, 0xf7, 0xab, 0x29, 0xd5, 0xdc, 0x47, 0x50, 0xa6, 0x94, 0x02, 0xa4, 0xb4, 0x97, 0x10, 0xa4, 0x7d, 0x4a, 0x36, 0xbe, 0xfe, 0xe9, 0x1f, 0xc4, 0x44, 0x63, 0x7b, 0x75, 0x55, 0x3b, 0xd5, 0x7b, 0xf7, 0x76, 0x16, 0x93, 0x01, 0xb3, 0xbe, 0xf0, 0x1c, 0xc4, 0x12, 0x2a, 0x51, 0x99, 0xa2, 0xf4, 0x9d, 0x22, 0x0a, 0x51, 0x8c, 0x96, 0x77, 0x4d, 0x94, 0x24, 0x32, 0x0a, 0xde, 0x5b, 0x7d, 0x53, 0x4b, 0x24, 0xab, 0xfc, 0x30, 0x99, 0xd8, 0x7c, 0x0b, 0x88, 0x8a, 0x75, 0x4d}
	tag02Body6 = []byte{0x04, 0x13, 0x16, 0x0a, 0x00, 0x30, 0x02, 0x9b, 0x03, 0x05, 0x82, 0x5b, 0x1a, 0x4e, 0x1d, 0x05, 0x89, 0x01, 0xdf, 0xe2, 0x00, 0x16, 0xa1, 0x04, 0x2b, 0x77, 0x57, 0xd8, 0xaf, 0x28, 0x34, 0x68, 0xa0, 0x57, 0x46, 0x99, 0x91, 0x0e, 0x55, 0x44, 0x78, 0xcc, 0xde, 0x00, 0x09, 0x90, 0x91, 0x0e, 0x55, 0x44, 0x78, 0xcc, 0xde, 0x00, 0x00, 0x00, 0xbd, 0xfc, 0x00, 0xfd, 0x17, 0xe2, 0xb2, 0xa9, 0xa4, 0xdd, 0x49, 0x9c, 0x67, 0xe8, 0xa2, 0x9d, 0x82, 0xb7, 0x0e, 0x8a, 0xe9, 0xee, 0xc4, 0x0d, 0x69, 0x67, 0xf6, 0xcf, 0xd9, 0x36, 0x01, 0x58, 0xb5, 0xe8, 0x8a, 0xb4, 0x00, 0xfb, 0x04, 0xe6, 0xf4, 0xad, 0x9a, 0x49, 0xcf, 0x58, 0xba, 0x56, 0xc9, 0x70, 0x51, 0x77, 0x5c, 0xa4, 0x09, 0x0f, 0x3b, 0xca, 0x78, 0x3c, 0xa4, 0x9e, 0x89, 0x3e, 0x4d, 0x5c, 0xd8, 0x21, 0x53, 0x08}
	tag02Body7 = []byte{0x05, 0x13, 0x16, 0x08, 0x00, 0x48, 0x22, 0x21, 0x05, 0x19, 0x34, 0x7b, 0xc9, 0x87, 0x24, 0x64, 0x02, 0x5f, 0x99, 0xdf, 0x3e, 0xc2, 0xe0, 0x00, 0x0e, 0xd9, 0x88, 0x48, 0x92, 0xe1, 0xf7, 0xb3, 0xea, 0x4c, 0x94, 0x00, 0x91, 0x59, 0x56, 0x9b, 0x54, 0x05, 0x02, 0x5c, 0x91, 0xf4, 0xe4, 0x02, 0x1b, 0x03, 0x05, 0x0b, 0x09, 0x08, 0x07, 0x02, 0x03, 0x22, 0x02, 0x01, 0x06, 0x15, 0x0a, 0x09, 0x08, 0x0b, 0x02, 0x04, 0x16, 0x02, 0x03, 0x01, 0x02, 0x1e, 0x07, 0x02, 0x17, 0x80, 0x00, 0x00, 0xf5, 0xc0, 0x00, 0xfe, 0x38, 0x91, 0xdf, 0x23, 0x2c, 0x64, 0xc7, 0x84, 0x43, 0x8d, 0x2e, 0xea, 0xec, 0xc4, 0xa1, 0x76, 0xba, 0x51, 0x77, 0x95, 0xfd, 0x2d, 0xf0, 0xc0, 0x90, 0x17, 0x44, 0x9c, 0xbd, 0x33, 0xcb, 0x34, 0x00, 0xff, 0x6f, 0xb8, 0xbf, 0xfb, 0x03, 0x24, 0xdf, 0x15, 0x7c, 0x30, 0xcd, 0x28, 0xc3, 0x9d, 0x89, 0xb3, 0x4b, 0x4a, 0x80, 0x85, 0xb2, 0xc3, 0x43, 0xae, 0x37, 0x37, 0xe3, 0x17, 0x18, 0x12, 0x76, 0x05}
	tag02Body8 = []byte{0x04, 0x10, 0x16, 0x08, 0x00, 0x34, 0x16, 0x21, 0x04, 0x3b, 0xcc, 0xc7, 0xcf, 0xd2, 0x59, 0x7e, 0x53, 0x44, 0xdd, 0x96, 0x4a, 0x72, 0x9b, 0x52, 0x3d, 0x11, 0xf3, 0xa8, 0xd7, 0x05, 0x02, 0x5e, 0xf0, 0x10, 0x12, 0x16, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x72, 0x65, 0x6d, 0x40, 0x67, 0x6e, 0x75, 0x70, 0x67, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x0a, 0x09, 0x10, 0x72, 0x9b, 0x52, 0x3d, 0x11, 0xf3, 0xa8, 0xd7, 0xb1, 0x15, 0x01, 0x00, 0xdf, 0x01, 0x42, 0xf0, 0xf3, 0x7d, 0x8c, 0xec, 0x85, 0x25, 0xa9, 0x34, 0xeb, 0xf3, 0x96, 0xa6, 0x56, 0x69, 0x40, 0x23, 0x2f, 0x04, 0x40, 0x4a, 0x26, 0x5f, 0xa1, 0x25, 0x96, 0x0b, 0x35, 0xd2, 0x01, 0x00, 0xf1, 0x19, 0x6b, 0x2d, 0x34, 0xe0, 0xbf, 0xc7, 0x0f, 0x40, 0x80, 0xe8, 0xef, 0x25, 0xf5, 0xe9, 0x90, 0xc8, 0x30, 0xa0, 0x95, 0x89, 0x13, 0xcb, 0x60, 0x08, 0xcf, 0x3a, 0x5e, 0x16, 0xf0, 0x01}
)

const (
	tag02Redult1 = `Signature Packet (tag 2) (94 bytes)
	04 01 13 08 00 06 05 02 54 c3 08 df 00 0a 09 10 31 fb fd a9 5f bb fa 18 36 1f 01 00 ea 1d a2 14 5b 82 06 fd d5 ae c4 9f d8 14 44 41 a4 f5 4f 56 69 ad 9a b0 44 f3 a3 88 b2 60 f4 0c 00 fc 0a d3 c0 23 f3 ed cd af 9b 19 6f ee c4 65 44 b5 08 e8 27 6c 3a a8 6e 3b 52 9f 61 7a ea ee 27 48
	Version: 4 (current)
		04
	Signiture Type: Signature of a canonical text document (0x01)
		01
	Public-key Algorithm: ECDSA public key algorithm (pub 19)
		13
	Hash Algorithm: SHA2-256 (hash 8)
		08
	Hashed Subpacket (6 bytes)
		05 02 54 c3 08 df
		Signature Creation Time (sub 2): 2015-01-24T02:52:15Z
			54 c3 08 df
	Unhashed Subpacket (10 bytes)
		09 10 31 fb fd a9 5f bb fa 18
		Issuer (sub 16): 0x31fbfda95fbbfa18
	Hash left 2 bytes
		36 1f
	ECDSA value r (256 bits)
		ea 1d a2 14 5b 82 06 fd d5 ae c4 9f d8 14 44 41 a4 f5 4f 56 69 ad 9a b0 44 f3 a3 88 b2 60 f4 0c
	ECDSA value s (252 bits)
		0a d3 c0 23 f3 ed cd af 9b 19 6f ee c4 65 44 b5 08 e8 27 6c 3a a8 6e 3b 52 9f 61 7a ea ee 27 48
`
	tag02Redult2 = `Signature Packet (tag 2) (117 bytes)
	04 00 11 08 00 1d 16 21 04 1b 52 02 db 4a 3e c7 76 f1 e0 ad 18 b4 da 3b ae 7e 20 b8 1c 05 02 5a 19 0d e4 00 0a 09 10 b4 da 3b ae 7e 20 b8 1c 73 3c 01 00 84 ef ee ae 22 69 2e af 33 b3 85 e1 ee aa 5d 2f 7a d4 ae a3 92 d3 e8 73 d4 b0 00 3e c9 2b 80 f7 00 ff 7c cc b9 d2 06 48 b3 39 58 9b a8 99 c5 c2 53 62 bd 8f 16 49 73 e0 65 fe a6 f7 18 1a 78 ff 65 e6
	Version: 4 (current)
		04
	Signiture Type: Signature of a binary document (0x00)
		00
	Public-key Algorithm: DSA (Digital Signature Algorithm) (pub 17)
		11
	Hash Algorithm: SHA2-256 (hash 8)
		08
	Hashed Subpacket (29 bytes)
		16 21 04 1b 52 02 db 4a 3e c7 76 f1 e0 ad 18 b4 da 3b ae 7e 20 b8 1c 05 02 5a 19 0d e4
		Issuer Fingerprint (sub 33) (21 bytes)
			04 1b 52 02 db 4a 3e c7 76 f1 e0 ad 18 b4 da 3b ae 7e 20 b8 1c
			Version: 4 (need 20 octets length)
			Fingerprint (20 bytes)
				1b 52 02 db 4a 3e c7 76 f1 e0 ad 18 b4 da 3b ae 7e 20 b8 1c
		Signature Creation Time (sub 2): 2017-11-25T06:29:56Z
			5a 19 0d e4
	Unhashed Subpacket (10 bytes)
		09 10 b4 da 3b ae 7e 20 b8 1c
		Issuer (sub 16): 0xb4da3bae7e20b81c
	Hash left 2 bytes
		73 3c
	DSA value r (256 bits)
		84 ef ee ae 22 69 2e af 33 b3 85 e1 ee aa 5d 2f 7a d4 ae a3 92 d3 e8 73 d4 b0 00 3e c9 2b 80 f7
	DSA value s (255 bits)
		7c cc b9 d2 06 48 b3 39 58 9b a8 99 c5 c2 53 62 bd 8f 16 49 73 e0 65 fe a6 f7 18 1a 78 ff 65 e6
`
	tag02Redult3 = `Signature Packet (tag 2) (103 bytes)
	04 18 13 08 00 0f 05 02 54 c3 01 bf 02 1b 0c 05 09 00 09 3a 80 00 0a 09 10 31 fb fd a9 5f bb fa 18 c6 27 01 00 c0 2f 76 5a 10 6d 1d 22 1e 62 c1 9b bc 62 d1 06 4a f1 3a 47 5a e9 0b f1 39 6c e3 67 a0 96 3c d2 01 00 8c 59 1c 3a 85 0e 1e d3 98 45 13 4d 30 e2 b9 a4 15 0e 1b 6d 66 1a a7 e7 d5 e2 51 07 95 60 87 91
	Version: 4 (current)
		04
	Signiture Type: Subkey Binding Signature (0x18)
		18
	Public-key Algorithm: ECDSA public key algorithm (pub 19)
		13
	Hash Algorithm: SHA2-256 (hash 8)
		08
	Hashed Subpacket (15 bytes)
		05 02 54 c3 01 bf 02 1b 0c 05 09 00 09 3a 80
		Signature Creation Time (sub 2): 2015-01-24T02:21:51Z
			54 c3 01 bf
		Key Flags (sub 27) (1 bytes)
			0c
			Flag: This key may be used to encrypt communications.
			Flag: This key may be used to encrypt storage.
		Key Expiration Time (sub 9): 7 days after (2015-01-31T02:21:51Z)
			00 09 3a 80
	Unhashed Subpacket (10 bytes)
		09 10 31 fb fd a9 5f bb fa 18
		Issuer (sub 16): 0x31fbfda95fbbfa18
	Hash left 2 bytes
		c6 27
	ECDSA value r (256 bits)
		c0 2f 76 5a 10 6d 1d 22 1e 62 c1 9b bc 62 d1 06 4a f1 3a 47 5a e9 0b f1 39 6c e3 67 a0 96 3c d2
	ECDSA value s (256 bits)
		8c 59 1c 3a 85 0e 1e d3 98 45 13 4d 30 e2 b9 a4 15 0e 1b 6d 66 1a a7 e7 d5 e2 51 07 95 60 87 91
`
	tag02Redult4 = `Signature Packet (tag 2) (149 bytes)
	03 05 00 36 5e ba 44 0f 64 8a 1c 9e 4f 74 4d 01 01 66 36 04 00 8f 8c 6b 45 a7 65 bd 37 f6 76 58 85 7c 39 66 7a c5 c1 48 f3 b8 85 69 7f 22 54 71 50 0e 97 b2 51 77 53 a2 22 d4 46 ec 0c 50 be ee e6 b0 c2 76 08 f0 6b 0e 6c fc e6 ef cd 10 3d 10 fd b3 87 40 20 55 6c 06 ae 41 c5 7c 0d 17 75 44 32 7d 08 41 45 95 da d6 57 74 58 38 72 6e f7 1f 63 ce d8 00 1b 25 37 23 b2 56 1a 02 9a ee 5a 57 f7 a3 ab 2d 89 20 85 1c c5 c0 ec 64 e9 2f 0b f5 4b 5f 2b 65 39
	Version: 3 (old)
		03
	Hashed material (5 bytes)
		Signiture Type: Signature of a binary document (0x00)
			00
		Signature creation time: 1998-11-27T14:42:12Z
			36 5e ba 44
	Key ID: 0x0f648a1c9e4f744d
	Public-key Algorithm: RSA (Encrypt or Sign) (pub 1)
		01
	Hash Algorithm: MD5 (hash 1)
		01
	Hash left 2 bytes
		66 36
	RSA signature value m^d mod n (1024 bits)
		8f 8c 6b 45 a7 65 bd 37 f6 76 58 85 7c 39 66 7a c5 c1 48 f3 b8 85 69 7f 22 54 71 50 0e 97 b2 51 77 53 a2 22 d4 46 ec 0c 50 be ee e6 b0 c2 76 08 f0 6b 0e 6c fc e6 ef cd 10 3d 10 fd b3 87 40 20 55 6c 06 ae 41 c5 7c 0d 17 75 44 32 7d 08 41 45 95 da d6 57 74 58 38 72 6e f7 1f 63 ce d8 00 1b 25 37 23 b2 56 1a 02 9a ee 5a 57 f7 a3 ab 2d 89 20 85 1c c5 c0 ec 64 e9 2f 0b f5 4b 5f 2b 65 39
`
	tag02Redult5 = `Signature Packet (tag 2) (308 bytes)
	04 13 01 08 00 1e 05 02 5a fa 85 65 02 9b 2f 05 8b 09 08 07 02 06 95 0a 09 08 0b 02 04 96 02 03 01 02 9e 01 00 0a 09 10 8e 3d ba 0e c4 dc c3 b7 ef 56 07 ff 63 cf 00 07 32 d7 4c 58 0b a3 81 0e d7 3e de 04 d4 f8 63 87 49 f3 3c 8a 36 47 30 25 15 5b 3a ea 75 95 53 70 31 be b9 23 2a a7 c5 b4 d7 56 cb 00 1c c6 03 f4 49 87 cd 07 d5 d4 1f c1 95 c1 f7 0e 16 27 54 da 4e a0 ea de 5b dd eb 4d 17 19 4b 61 30 52 d0 02 50 16 5a b5 cf a7 64 2c 89 ff 67 12 9b ce b6 ba 92 a4 61 25 96 06 14 23 ed 6d 30 8f e5 26 9c 66 5b 6f 34 05 66 13 b7 cd 90 bc 38 84 af 5f 8f 20 07 d0 e5 bd 17 23 4f 2a 5d 37 17 d8 f8 b4 2f e6 be 28 79 bc 00 05 18 ac ab d6 ea 9d f4 6c 1a dd c9 6a 87 9e 19 2f ff 12 aa 69 49 3e 93 ee 78 8c f7 ab 29 d5 dc 47 50 a6 94 02 a4 b4 97 10 a4 7d 4a 36 be fe e9 1f c4 44 63 7b 75 55 3b d5 7b f7 76 16 93 01 b3 be f0 1c c4 12 2a 51 99 a2 f4 9d 22 0a 51 8c 96 77 4d 94 24 32 0a de 5b 7d 53 4b 24 ab fc 30 99 d8 7c 0b 88 8a 75 4d
	Version: 4 (current)
		04
	Signiture Type: Positive certification of a User ID and Public-Key packet (0x13)
		13
	Public-key Algorithm: RSA (Encrypt or Sign) (pub 1)
		01
	Hash Algorithm: SHA2-256 (hash 8)
		08
	Hashed Subpacket (30 bytes)
		05 02 5a fa 85 65 02 9b 2f 05 8b 09 08 07 02 06 95 0a 09 08 0b 02 04 96 02 03 01 02 9e 01
		Signature Creation Time (sub 2): 2018-05-15T06:59:49Z
			5a fa 85 65
		Key Flags <critical> (sub 27) (1 bytes)
			2f
			Flag: This key may be used to certify other keys.
			Flag: This key may be used to sign data.
			Flag: This key may be used to encrypt communications.
			Flag: This key may be used to encrypt storage.
			Flag: This key may be used for authentication.
		Preferred Symmetric Algorithms <critical> (sub 11) (4 bytes)
			09 08 07 02
			Symmetric Algorithm: AES with 256-bit key (sym 9)
				09
			Symmetric Algorithm: AES with 192-bit key (sym 8)
				08
			Symmetric Algorithm: AES with 128-bit key (sym 7)
				07
			Symmetric Algorithm: TripleDES (168 bit key derived from 192) (sym 2)
				02
		Preferred Hash Algorithms <critical> (sub 21) (5 bytes)
			0a 09 08 0b 02
			Hash Algorithm: SHA2-512 (hash 10)
				0a
			Hash Algorithm: SHA2-384 (hash 9)
				09
			Hash Algorithm: SHA2-256 (hash 8)
				08
			Hash Algorithm: SHA2-224 (hash 11)
				0b
			Hash Algorithm: SHA-1 (hash 2)
				02
		Preferred Compression Algorithms <critical> (sub 22) (3 bytes)
			02 03 01
			Compression Algorithm: ZLIB <RFC1950> (comp 2)
				02
			Compression Algorithm: BZip2 (comp 3)
				03
			Compression Algorithm: ZIP <RFC1951> (comp 1)
				01
		Features <critical> (sub 30) (1 bytes)
			01
			Flag: Modification Detection (packets 18 and 19)
	Unhashed Subpacket (10 bytes)
		09 10 8e 3d ba 0e c4 dc c3 b7
		Issuer (sub 16): 0x8e3dba0ec4dcc3b7
	Hash left 2 bytes
		ef 56
	RSA signature value m^d mod n (2047 bits)
		63 cf 00 07 32 d7 4c 58 0b a3 81 0e d7 3e de 04 d4 f8 63 87 49 f3 3c 8a 36 47 30 25 15 5b 3a ea 75 95 53 70 31 be b9 23 2a a7 c5 b4 d7 56 cb 00 1c c6 03 f4 49 87 cd 07 d5 d4 1f c1 95 c1 f7 0e 16 27 54 da 4e a0 ea de 5b dd eb 4d 17 19 4b 61 30 52 d0 02 50 16 5a b5 cf a7 64 2c 89 ff 67 12 9b ce b6 ba 92 a4 61 25 96 06 14 23 ed 6d 30 8f e5 26 9c 66 5b 6f 34 05 66 13 b7 cd 90 bc 38 84 af 5f 8f 20 07 d0 e5 bd 17 23 4f 2a 5d 37 17 d8 f8 b4 2f e6 be 28 79 bc 00 05 18 ac ab d6 ea 9d f4 6c 1a dd c9 6a 87 9e 19 2f ff 12 aa 69 49 3e 93 ee 78 8c f7 ab 29 d5 dc 47 50 a6 94 02 a4 b4 97 10 a4 7d 4a 36 be fe e9 1f c4 44 63 7b 75 55 3b d5 7b f7 76 16 93 01 b3 be f0 1c c4 12 2a 51 99 a2 f4 9d 22 0a 51 8c 96 77 4d 94 24 32 0a de 5b 7d 53 4b 24 ab fc 30 99 d8 7c 0b 88 8a 75 4d
`
	tag02Redult6 = `Signature Packet (tag 2) (126 bytes)
	04 13 16 0a 00 30 02 9b 03 05 82 5b 1a 4e 1d 05 89 01 df e2 00 16 a1 04 2b 77 57 d8 af 28 34 68 a0 57 46 99 91 0e 55 44 78 cc de 00 09 90 91 0e 55 44 78 cc de 00 00 00 bd fc 00 fd 17 e2 b2 a9 a4 dd 49 9c 67 e8 a2 9d 82 b7 0e 8a e9 ee c4 0d 69 67 f6 cf d9 36 01 58 b5 e8 8a b4 00 fb 04 e6 f4 ad 9a 49 cf 58 ba 56 c9 70 51 77 5c a4 09 0f 3b ca 78 3c a4 9e 89 3e 4d 5c d8 21 53 08
	Version: 4 (current)
		04
	Signiture Type: Positive certification of a User ID and Public-Key packet (0x13)
		13
	Public-key Algorithm: EdDSA (pub 22)
		16
	Hash Algorithm: SHA2-512 (hash 10)
		0a
	Hashed Subpacket (48 bytes)
		02 9b 03 05 82 5b 1a 4e 1d 05 89 01 df e2 00 16 a1 04 2b 77 57 d8 af 28 34 68 a0 57 46 99 91 0e 55 44 78 cc de 00 09 90 91 0e 55 44 78 cc de 00
		Key Flags <critical> (sub 27) (1 bytes)
			03
			Flag: This key may be used to certify other keys.
			Flag: This key may be used to sign data.
		Signature Creation Time <critical> (sub 2): 2018-06-08T09:36:29Z
			5b 1a 4e 1d
		Key Expiration Time <critical> (sub 9): 364 days after (2019-06-07T09:36:29Z)
			01 df e2 00
		Issuer Fingerprint <critical> (sub 33) (21 bytes)
			04 2b 77 57 d8 af 28 34 68 a0 57 46 99 91 0e 55 44 78 cc de 00
			Version: 4 (need 20 octets length)
			Fingerprint (20 bytes)
				2b 77 57 d8 af 28 34 68 a0 57 46 99 91 0e 55 44 78 cc de 00
		Issuer <critical> (sub 16): 0x910e554478ccde00
	Hash left 2 bytes
		bd fc
	EC point r (253 bits)
		17 e2 b2 a9 a4 dd 49 9c 67 e8 a2 9d 82 b7 0e 8a e9 ee c4 0d 69 67 f6 cf d9 36 01 58 b5 e8 8a b4
	EdDSA value s in the little endian representation (251 bits)
		04 e6 f4 ad 9a 49 cf 58 ba 56 c9 70 51 77 5c a4 09 0f 3b ca 78 3c a4 9e 89 3e 4d 5c d8 21 53 08
`
	tag02Redult7 = `Signature Packet (tag 2) (150 bytes)
	05 13 16 08 00 48 22 21 05 19 34 7b c9 87 24 64 02 5f 99 df 3e c2 e0 00 0e d9 88 48 92 e1 f7 b3 ea 4c 94 00 91 59 56 9b 54 05 02 5c 91 f4 e4 02 1b 03 05 0b 09 08 07 02 03 22 02 01 06 15 0a 09 08 0b 02 04 16 02 03 01 02 1e 07 02 17 80 00 00 f5 c0 00 fe 38 91 df 23 2c 64 c7 84 43 8d 2e ea ec c4 a1 76 ba 51 77 95 fd 2d f0 c0 90 17 44 9c bd 33 cb 34 00 ff 6f b8 bf fb 03 24 df 15 7c 30 cd 28 c3 9d 89 b3 4b 4a 80 85 b2 c3 43 ae 37 37 e3 17 18 12 76 05
	Version: 5 (draft)
		05
	Signiture Type: Positive certification of a User ID and Public-Key packet (0x13)
		13
	Public-key Algorithm: EdDSA (pub 22)
		16
	Hash Algorithm: SHA2-256 (hash 8)
		08
	Hashed Subpacket (72 bytes)
		22 21 05 19 34 7b c9 87 24 64 02 5f 99 df 3e c2 e0 00 0e d9 88 48 92 e1 f7 b3 ea 4c 94 00 91 59 56 9b 54 05 02 5c 91 f4 e4 02 1b 03 05 0b 09 08 07 02 03 22 02 01 06 15 0a 09 08 0b 02 04 16 02 03 01 02 1e 07 02 17 80
		Issuer Fingerprint (sub 33) (33 bytes)
			05 19 34 7b c9 87 24 64 02 5f 99 df 3e c2 e0 00 0e d9 88 48 92 e1 f7 b3 ea 4c 94 00 91 59 56 9b 54
			Version: 5 (need 32 octets length)
			Fingerprint (32 bytes)
				19 34 7b c9 87 24 64 02 5f 99 df 3e c2 e0 00 0e d9 88 48 92 e1 f7 b3 ea 4c 94 00 91 59 56 9b 54
		Signature Creation Time (sub 2): 2019-03-20T08:08:04Z
			5c 91 f4 e4
		Key Flags (sub 27) (1 bytes)
			03
			Flag: This key may be used to certify other keys.
			Flag: This key may be used to sign data.
		Preferred Symmetric Algorithms (sub 11) (4 bytes)
			09 08 07 02
			Symmetric Algorithm: AES with 256-bit key (sym 9)
				09
			Symmetric Algorithm: AES with 192-bit key (sym 8)
				08
			Symmetric Algorithm: AES with 128-bit key (sym 7)
				07
			Symmetric Algorithm: TripleDES (168 bit key derived from 192) (sym 2)
				02
		Preferred AEAD Algorithms (sub 34) (2 bytes)
			02 01
			AEAD Algorithm: OCB mode <RFC7253> (aead 2)
				02
			AEAD Algorithm: EAX mode (aead 1)
				01
		Preferred Hash Algorithms (sub 21) (5 bytes)
			0a 09 08 0b 02
			Hash Algorithm: SHA2-512 (hash 10)
				0a
			Hash Algorithm: SHA2-384 (hash 9)
				09
			Hash Algorithm: SHA2-256 (hash 8)
				08
			Hash Algorithm: SHA2-224 (hash 11)
				0b
			Hash Algorithm: SHA-1 (hash 2)
				02
		Preferred Compression Algorithms (sub 22) (3 bytes)
			02 03 01
			Compression Algorithm: ZLIB <RFC1950> (comp 2)
				02
			Compression Algorithm: BZip2 (comp 3)
				03
			Compression Algorithm: ZIP <RFC1951> (comp 1)
				01
		Features (sub 30) (1 bytes)
			07
			Flag: Modification Detection (packets 18 and 19)
			Flag: AEAD Encrypted Data Packet (packet 20) and version 5 Symmetric-Key Encrypted Session Key Packets (packet 3)
			Flag: Version 5 Public-Key Packet format and corresponding new fingerprint format
		Key Server Preferences (sub 23) (1 bytes)
			80
			Flag: No-modify
	Hash left 2 bytes
		f5 c0
	EC point r (254 bits)
		38 91 df 23 2c 64 c7 84 43 8d 2e ea ec c4 a1 76 ba 51 77 95 fd 2d f0 c0 90 17 44 9c bd 33 cb 34
	EdDSA value s in the little endian representation (255 bits)
		6f b8 bf fb 03 24 df 15 7c 30 cd 28 c3 9d 89 b3 4b 4a 80 85 b2 c3 43 ae 37 37 e3 17 18 12 76 05
`
	tag02Redult8 = `Signature Packet (tag 2) (140 bytes)
	04 10 16 08 00 34 16 21 04 3b cc c7 cf d2 59 7e 53 44 dd 96 4a 72 9b 52 3d 11 f3 a8 d7 05 02 5e f0 10 12 16 14 80 00 00 00 00 0d 00 00 72 65 6d 40 67 6e 75 70 67 2e 6f 72 67 00 0a 09 10 72 9b 52 3d 11 f3 a8 d7 b1 15 01 00 df 01 42 f0 f3 7d 8c ec 85 25 a9 34 eb f3 96 a6 56 69 40 23 2f 04 40 4a 26 5f a1 25 96 0b 35 d2 01 00 f1 19 6b 2d 34 e0 bf c7 0f 40 80 e8 ef 25 f5 e9 90 c8 30 a0 95 89 13 cb 60 08 cf 3a 5e 16 f0 01
	Version: 4 (current)
		04
	Signiture Type: Generic certification of a User ID and Public-Key packet (0x10)
		10
	Public-key Algorithm: EdDSA (pub 22)
		16
	Hash Algorithm: SHA2-256 (hash 8)
		08
	Hashed Subpacket (52 bytes)
		16 21 04 3b cc c7 cf d2 59 7e 53 44 dd 96 4a 72 9b 52 3d 11 f3 a8 d7 05 02 5e f0 10 12 16 14 80 00 00 00 00 0d 00 00 72 65 6d 40 67 6e 75 70 67 2e 6f 72 67
		Issuer Fingerprint (sub 33) (21 bytes)
			04 3b cc c7 cf d2 59 7e 53 44 dd 96 4a 72 9b 52 3d 11 f3 a8 d7
			Version: 4 (need 20 octets length)
			Fingerprint (20 bytes)
				3b cc c7 cf d2 59 7e 53 44 dd 96 4a 72 9b 52 3d 11 f3 a8 d7
		Signature Creation Time (sub 2): 2020-06-22T01:57:38Z
			5e f0 10 12
		Notation Data (sub 20) (21 bytes)
			80 00 00 00 00 0d 00 00 72 65 6d 40 67 6e 75 70 67 2e 6f 72 67
			Flag: Human-readable
			Name: rem@gnupg.org
				72 65 6d 40 67 6e 75 70 67 2e 6f 72 67
			Value (0 byte)
	Unhashed Subpacket (10 bytes)
		09 10 72 9b 52 3d 11 f3 a8 d7
		Issuer (sub 16): 0x729b523d11f3a8d7
	Hash left 2 bytes
		b1 15
	EC point r (256 bits)
		df 01 42 f0 f3 7d 8c ec 85 25 a9 34 eb f3 96 a6 56 69 40 23 2f 04 40 4a 26 5f a1 25 96 0b 35 d2
	EdDSA value s in the little endian representation (256 bits)
		f1 19 6b 2d 34 e0 bf c7 0f 40 80 e8 ef 25 f5 e9 90 c8 30 a0 95 89 13 cb 60 08 cf 3a 5e 16 f0 01
`
)

func TestTag02(t *testing.T) {
	testCases := []struct {
		tag     uint8
		content []byte
		ktm     []byte
		cxt     context.SymAlgMode
		res     string
	}{
		{tag: 2, content: tag02Body1, ktm: nil, cxt: context.ModeNotSpecified, res: tag02Redult1},
		{tag: 2, content: tag02Body2, ktm: nil, cxt: context.ModeNotSpecified, res: tag02Redult2},
		{tag: 2, content: tag02Body3, ktm: []byte{0x54, 0xc3, 0x01, 0xbf}, cxt: context.ModeNotSpecified, res: tag02Redult3},
		{tag: 2, content: tag02Body4, ktm: []byte{0x54, 0xc3, 0x01, 0xbf}, cxt: context.ModeNotSpecified, res: tag02Redult4},
		{tag: 2, content: tag02Body5, ktm: []byte{0x54, 0xc3, 0x01, 0xbf}, cxt: context.ModeNotSpecified, res: tag02Redult5},
		{tag: 2, content: tag02Body6, ktm: []byte{0x5b, 0x1a, 0x4e, 0x1d}, cxt: context.ModeNotSpecified, res: tag02Redult6},
		{tag: 2, content: tag02Body7, ktm: []byte{0x5b, 0x1a, 0x4e, 0x1d}, cxt: context.ModeNotSpecified, res: tag02Redult7},
		{tag: 2, content: tag02Body8, ktm: []byte{0x5b, 0x1a, 0x4e, 0x1d}, cxt: context.ModeNotSpecified, res: tag02Redult8},
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
