package pubkey

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/options"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

var (
	pubkeySig19      = []byte{0x01, 0x00, 0xea, 0x1d, 0xa2, 0x14, 0x5b, 0x82, 0x06, 0xfd, 0xd5, 0xae, 0xc4, 0x9f, 0xd8, 0x14, 0x44, 0x41, 0xa4, 0xf5, 0x4f, 0x56, 0x69, 0xad, 0x9a, 0xb0, 0x44, 0xf3, 0xa3, 0x88, 0xb2, 0x60, 0xf4, 0x0c, 0x00, 0xfc, 0x0a, 0xd3, 0xc0, 0x23, 0xf3, 0xed, 0xcd, 0xaf, 0x9b, 0x19, 0x6f, 0xee, 0xc4, 0x65, 0x44, 0xb5, 0x08, 0xe8, 0x27, 0x6c, 0x3a, 0xa8, 0x6e, 0x3b, 0x52, 0x9f, 0x61, 0x7a, 0xea, 0xee, 0x27, 0x48}
	pubkeySigUnknown = []byte{0x01, 0x02, 0x03, 0x04}
)

var (
	pubkeySigName19a = "ECDSA value r"
	pubkeySigNote19a = "256 bits"
	pubkeySigName19b = "ECDSA value s"
	pubkeySigNote19b = "252 bits"
	//pubkeySigName19b = "ECDH 04 || EC point (X,Y)"
	//pubkeySigNote19b = "515 bits"
)

const (
	pubkeySigResult19 = `
	ECDSA value r (256 bits)
		ea 1d a2 14 5b 82 06 fd d5 ae c4 9f d8 14 44 41 a4 f5 4f 56 69 ad 9a b0 44 f3 a3 88 b2 60 f4 0c
	ECDSA value s (252 bits)
		0a d3 c0 23 f3 ed cd af 9b 19 6f ee c4 65 44 b5 08 e8 27 6c 3a a8 6e 3b 52 9f 61 7a ea ee 27 48
`
	pubkeySigResultUnknown = `
	Multi-precision integers of Unknown (pub 99) (4 bytes)
		01 02 03 04
`
)

var cxtSig = context.NewContext(options.New(
	options.Set(options.DebugOpt, true), //not use
	options.Set(options.GDumpOpt, true), //not use
	options.Set(options.IntegerOpt, true),
	options.Set(options.LiteralOpt, true),
	options.Set(options.MarkerOpt, true),
	options.Set(options.PrivateOpt, true),
	options.Set(options.UTCOpt, true),
))

func TestPubkeySig19(t *testing.T) {
	parent := info.NewItem()
	if err := New(cxtSig, values.PubID(19), reader.New(pubkeySig19)).ParseSig(parent); err != nil {
		t.Errorf("ParseSig() = %v, want nil error.", err)
	}
	str := parent.String()
	if str != pubkeySigResult19 {
		t.Errorf("pubkey.ParseSig() = \"%v\", want \"%v\".", str, pubkeySigResult19)
	}
}

func TestPubkeySigUnknown(t *testing.T) {
	parent := info.NewItem()
	if err := New(cxtSig, values.PubID(99), reader.New(pubkeySigUnknown)).ParseSig(parent); err != nil {
		t.Errorf("ParseSig() = %v, want nil error.", err)
	}
	str := parent.String()
	if str != pubkeySigResultUnknown {
		t.Errorf("pubkey.ParseSig() = \"%v\", want \"%v\".", str, pubkeySigResultUnknown)
	}
}

/* Copyright 2016,2017 Spiegel
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
