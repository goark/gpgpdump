package tags

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"

	"golang.org/x/crypto/openpgp/packet"
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

func TestTag03(t *testing.T) {
	testCases := []struct {
		tag     uint8
		content []byte
		ktm     []byte
		cxt     context.SymAlgMode
		res     string
	}{
		{tag: 3, content: tag03Body1, ktm: nil, cxt: context.ModeSymEnc, res: tag03Result1},
		{tag: 3, content: tag03Body2, ktm: nil, cxt: context.ModeSymEnc, res: tag03Result2},
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
