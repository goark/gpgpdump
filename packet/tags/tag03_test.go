package tags

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/options"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"

	openpgp "golang.org/x/crypto/openpgp/packet"
)

var (
	tag03Body1 = []byte{0x04, 0x03, 0x00, 0x01}
	tag03Body2 = []byte{0x04, 0x04, 0x01, 0x03, 0xab, 0x2b, 0xb0, 0x87, 0xb4, 0x1d, 0x43, 0x48}
)

const (
	tag03Result1 = `Symmetric-Key Encrypted Session Key Packet (tag 3) (4 bytes)
	04 03 00 01
	Version: 4 (current)
		04
	Symmetric Algorithm: CAST5 (128 bit key, as per) (sym 3)
		03
	String-to-Key (S2K) Algorithm: Simple S2K (s2k 0)
		00
		Hash Algorithm: MD5 (hash 1)
			01
`
	tag03Result2 = `Symmetric-Key Encrypted Session Key Packet (tag 3) (12 bytes)
	04 04 01 03 ab 2b b0 87 b4 1d 43 48
	Version: 4 (current)
		04
	Symmetric Algorithm: Blowfish (128 bit key, 16 rounds) (sym 4)
		04
	String-to-Key (S2K) Algorithm: Salted S2K (s2k 1)
		01
		Hash Algorithm: RIPE-MD/160 (hash 3)
			03
		Salt
			ab 2b b0 87 b4 1d 43 48
`
)

func TestTag03a(t *testing.T) {
	op := &openpgp.OpaquePacket{Tag: 3, Contents: tag03Body1}
	cxt := context.NewContext(options.New(
		options.Set(options.DebugOpt, true),
		options.Set(options.IntegerOpt, true),
		options.Set(options.MarkerOpt, true),
		options.Set(options.LiteralOpt, true),
		options.Set(options.PrivateOpt, true),
		options.Set(options.UTCOpt, true),
	))
	i, err := NewTag(op, cxt).Parse()
	if err != nil {
		t.Errorf("NewTag() = %v, want nil error.", err)
		return
	}
	if cxt.AlgMode() != context.ModeSymEnc {
		t.Errorf("Options.Mode = %v, want \"%v\".", cxt.AlgMode(), context.ModeSymEnc)
	}
	str := i.String()
	if str != tag03Result1 {
		t.Errorf("Tag.String = \"%s\", want \"%s\".", str, tag03Result1)
	}
}

func TestTag03b(t *testing.T) {
	op := &openpgp.OpaquePacket{Tag: 3, Contents: tag03Body2}
	cxt := context.NewContext(options.New(
		options.Set(options.DebugOpt, true),
		options.Set(options.IntegerOpt, true),
		options.Set(options.MarkerOpt, true),
		options.Set(options.LiteralOpt, true),
		options.Set(options.PrivateOpt, true),
		options.Set(options.UTCOpt, true),
	))
	i, err := NewTag(op, cxt).Parse()
	if err != nil {
		t.Errorf("NewTag() = %v, want nil error.", err)
		return
	}
	if cxt.AlgMode() != context.ModeSymEnc {
		t.Errorf("Options.Mode = %v, want \"%v\".", cxt.AlgMode(), context.ModeSymEnc)
	}
	str := i.String()
	if str != tag03Result2 {
		t.Errorf("Tag.String = \"%s\", want \"%s\".", str, tag03Result2)
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
