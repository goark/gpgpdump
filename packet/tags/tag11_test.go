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
	tag11Body1 = []byte{0x62, 0x00, 0x5a, 0x19, 0x0d, 0xe4, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x0d, 0x0a}
	tag11Body2 = []byte{0x62, 0x04, 0x68, 0x6f, 0x67, 0x65, 0x0a, 0x00, 0x04, 0x50, 0x1b, 0x24, 0x42, 0x3b, 0x33, 0x4b, 0x5c, 0x4f, 0x42, 0x49, 0x27, 0x24, 0x47, 0x24, 0x39, 0x21, 0x23, 0x1b, 0x28, 0x42, 0x0a, 0x1b, 0x24, 0x42, 0x24, 0x3d, 0x24, 0x6c, 0x21, 0x23, 0x1b, 0x28, 0x42, 0x0a, 0x0a}
)

const (
	tag11Result1 = `Literal Data Packet (tag 11) (19 bytes)
	62 00 5a 19 0d e4 48 65 6c 6c 6f 20 77 6f 72 6c 64 0d 0a
	Literal data format: b (binary)
	File name: <null>
	Modification time of a file: 2017-11-25T06:29:56Z
		5a 19 0d e4
	Literal data (13 bytes)
		48 65 6c 6c 6f 20 77 6f 72 6c 64 0d 0a
`
	tag11Result2 = `Literal Data Packet (tag 11) (45 bytes)
	62 04 68 6f 67 65 0a 00 04 50 1b 24 42 3b 33 4b 5c 4f 42 49 27 24 47 24 39 21 23 1b 28 42 0a 1b 24 42 24 3d 24 6c 21 23 1b 28 42 0a 0a
	Literal data format: b (binary)
	File name: hoge
		68 6f 67 65
	Modification time of a file: 1975-04-26T19:41:04Z
		0a 00 04 50
	Literal data (35 bytes)
		1b 24 42 3b 33 4b 5c 4f 42 49 27 24 47 24 39 21 23 1b 28 42 0a 1b 24 42 24 3d 24 6c 21 23 1b 28 42 0a 0a
`
)

func TestTag11(t *testing.T) {
	testCases := []struct {
		tag     uint8
		content []byte
		ktm     []byte
		cxt     context.SymAlgMode
		res     string
	}{
		{tag: 11, content: tag11Body1, ktm: nil, cxt: context.ModeNotSpecified, res: tag11Result1},
		{tag: 11, content: tag11Body2, ktm: nil, cxt: context.ModeNotSpecified, res: tag11Result2},
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
