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
	pubkeySes17  = []byte{17, 0x02, 0x03, 0x04}
	pubkeySes18a = []byte{0x12, 0x02, 0x03, 0x04, 0xc3, 0xe7, 0xd7, 0x2b, 0xaf, 0x25, 0x2a, 0x19, 0xf6, 0x27, 0x80, 0xea, 0x7c, 0x4f, 0x6d, 0xca, 0x61, 0x22, 0x5a, 0xe3, 0xad, 0x0c, 0xfb, 0xd9, 0xa2, 0xd5, 0xa4, 0x30, 0x9a, 0xf3, 0xee, 0x34, 0x54, 0xae, 0xa8, 0xf6, 0x46, 0xac, 0x8a, 0xae, 0x38, 0xa6, 0x4f, 0xf3, 0xf2, 0xee, 0x30, 0x40, 0x62, 0x5b, 0x07, 0xe7, 0x2b, 0xee, 0x9a, 0x90, 0xd4, 0x6f, 0x1e, 0xd7, 0xc3, 0x26, 0x21, 0xab, 0x30, 0x4a, 0xfe, 0x88, 0xa2, 0x9f, 0x0e, 0xab, 0xf3, 0xbe, 0x7a, 0x89, 0x27, 0x32, 0x38, 0xb8, 0x06, 0x75, 0xfc, 0xac, 0x3c, 0xd4, 0xba, 0x0f, 0x49, 0x64, 0x15, 0xaa, 0x48, 0x9a, 0xdb, 0xc1, 0x8a, 0x7b, 0x11, 0x76, 0xfb, 0x2f, 0xef, 0xef, 0xb0, 0x29, 0xa9, 0x24, 0x75, 0x6d, 0x69, 0x12, 0x4d}
	pubkeySes18b = []byte{0x12, 0x02, 0x03, 0x04}
	pubkeySes18c = []byte{0x12, 0x02, 0x03, 0x04, 0xc3, 0xe7, 0xd7, 0x2b, 0xaf, 0x25, 0x2a, 0x19, 0xf6, 0x27, 0x80, 0xea, 0x7c, 0x4f, 0x6d, 0xca, 0x61, 0x22, 0x5a, 0xe3, 0xad, 0x0c, 0xfb, 0xd9, 0xa2, 0xd5, 0xa4, 0x30, 0x9a, 0xf3, 0xee, 0x34, 0x54, 0xae, 0xa8, 0xf6, 0x46, 0xac, 0x8a, 0xae, 0x38, 0xa6, 0x4f, 0xf3, 0xf2, 0xee, 0x30, 0x40, 0x62, 0x5b, 0x07, 0xe7, 0x2b, 0xee, 0x9a, 0x90, 0xd4, 0x6f, 0x1e, 0xd7, 0xc3, 0x26, 0x21, 0xab, 0x30, 0x4a, 0xfe, 0x88, 0xa2, 0x9f, 0x0e, 0xab, 0xf3, 0xbe}
	pubkeySes19  = []byte{19, 0x02, 0x03, 0x04}
	pubkeySesUn  = []byte{100, 0x02, 0x03, 0x04}
)

var (
	pubkeySesName18a = "Multi-precision integer"
	pubkeySesName18b = "symmetric key (encoded)"
	pubkeySesName17  = "Multi-precision integers of DSA"
	pubkeySesName19  = "Multi-precision integers of ECDSA"
	pubkeySesNameUn  = "Multi-precision integers of Unknown (pub 100)"
)

var cxtPub = context.NewContext(options.NewOptions(
	options.Set(options.DebugOpt, true), //not use
	options.Set(options.GDumpOpt, true), //not use
	options.Set(options.IntegerOpt, true),
	options.Set(options.LiteralOpt, true),
	options.Set(options.MarkerOpt, true),
	options.Set(options.PrivateOpt, true),
	options.Set(options.UTCOpt, true),
))

func TestPubkeySes17(t *testing.T) {
	parent := info.NewItem()
	New(cxtPub, values.PubID(pubkeySes17[0]), reader.New(pubkeySes17[1:])).ParseSes(parent)
	if len(parent.Items) != 1 {
		t.Errorf("Count of Items = %v, want 1.", len(parent.Items))
	} else if parent.Items[0].Name != pubkeySesName17 {
		t.Errorf("Pubkey Name = \"%s\" (%s), want \"%s\".", parent.Items[0].Name, parent.Items[0].Note, pubkeySesName17)
	}
}

func TestPubkeySes18(t *testing.T) {
	parent := info.NewItem()
	New(cxtPub, values.PubID(pubkeySes18a[0]), reader.New(pubkeySes18a[1:])).ParseSes(parent)
	if len(parent.Items) != 2 {
		t.Errorf("Count of Items = %v, want 2.", len(parent.Items))
	} else if parent.Items[0].Name != pubkeySesName18a {
		t.Errorf("Pubkey Name = \"%s\" (%s), want \"%s\".", parent.Items[0].Name, parent.Items[0].Note, pubkeySesName18a)
	} else if parent.Items[1].Name != pubkeySesName18b {
		t.Errorf("Pubkey Name = \"%s\" (%s), want \"%s\".", parent.Items[1].Name, parent.Items[1].Note, pubkeySesName18b)
	}
}

func TestPubkeySes18Err1(t *testing.T) {
	parent := info.NewItem()
	New(cxtPub, values.PubID(pubkeySes18b[0]), reader.New(pubkeySes18b[1:])).ParseSes(parent)
	if len(parent.Items) != 0 {
		t.Errorf("Count of Items = %v, want 0.", len(parent.Items))
	}
}

func TestPubkeySes18Err2(t *testing.T) {
	parent := info.NewItem()
	New(cxtPub, values.PubID(pubkeySes18c[0]), reader.New(pubkeySes18c[1:])).ParseSes(parent)
	if len(parent.Items) != 1 {
		t.Errorf("Count of Items = %v, want 1.", len(parent.Items))
	} else if parent.Items[0].Name != pubkeySesName18a {
		t.Errorf("Pubkey Name = \"%s\" (%s), want \"%s\".", parent.Items[0].Name, parent.Items[0].Note, pubkeySesName18a)
	}
}

func TestPubkeySes19(t *testing.T) {
	parent := info.NewItem()
	New(cxtPub, values.PubID(pubkeySes19[0]), reader.New(pubkeySes19[1:])).ParseSes(parent)
	if len(parent.Items) != 1 {
		t.Errorf("Count of Items = %v, want 1.", len(parent.Items))
	} else if parent.Items[0].Name != pubkeySesName19 {
		t.Errorf("Pubkey Name = \"%s\" (%s), want \"%s\".", parent.Items[0].Name, parent.Items[0].Note, pubkeySesName19)
	}
}

func TestPubkeySesUnknown(t *testing.T) {
	parent := info.NewItem()
	New(cxtPub, values.PubID(pubkeySesUn[0]), reader.New(pubkeySesUn[1:])).ParseSes(parent)
	if len(parent.Items) != 1 {
		t.Errorf("Count of Items = %v, want 1.", len(parent.Items))
	} else if parent.Items[0].Name != pubkeySesNameUn {
		t.Errorf("Pubkey Name = \"%s\" (%s), want \"%s\".", parent.Items[0].Name, parent.Items[0].Note, pubkeySesNameUn)
	}
}

/* Copyright 2016 Spiegel
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
