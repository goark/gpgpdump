package tags

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/options"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"

	openpgp "golang.org/x/crypto/openpgp/packet"
)

var (
	tag09Body1 = []byte{0xe7, 0x2d, 0x2f, 0xb1, 0xf1, 0x0f, 0xc3, 0xce, 0x55, 0x5d, 0xb2, 0x8a, 0x4b, 0xe8, 0x4f, 0x43, 0x15, 0x6e, 0x7d, 0x90, 0x90, 0x53, 0x6a, 0x9a, 0xe3, 0xaa, 0x1c, 0x68, 0xd6, 0xd3, 0xfc, 0x6a, 0x4e, 0x79, 0xa8, 0xe7, 0xb1, 0xa5, 0x87, 0xea, 0xcc, 0xcc, 0x99, 0x66, 0x31, 0xad, 0xff, 0xe1, 0xa3, 0x03, 0xb6, 0x47, 0x85, 0x76, 0xbd, 0x0b}
)

const (
	tag09Result1a = `Symmetrically Encrypted Data Packet (tag 9) (56 bytes)
	e7 2d 2f b1 f1 0f c3 ce 55 5d b2 8a 4b e8 4f 43 15 6e 7d 90 90 53 6a 9a e3 aa 1c 68 d6 d3 fc 6a 4e 79 a8 e7 b1 a5 87 ea cc cc 99 66 31 ad ff e1 a3 03 b6 47 85 76 bd 0b
	Encrypted data: sym alg is specified in sym-key encrypted session key (56 bytes)
		e7 2d 2f b1 f1 0f c3 ce 55 5d b2 8a 4b e8 4f 43 15 6e 7d 90 90 53 6a 9a e3 aa 1c 68 d6 d3 fc 6a 4e 79 a8 e7 b1 a5 87 ea cc cc 99 66 31 ad ff e1 a3 03 b6 47 85 76 bd 0b
`
	tag09Result1b = `Symmetrically Encrypted Data Packet (tag 9) (56 bytes)
	e7 2d 2f b1 f1 0f c3 ce 55 5d b2 8a 4b e8 4f 43 15 6e 7d 90 90 53 6a 9a e3 aa 1c 68 d6 d3 fc 6a 4e 79 a8 e7 b1 a5 87 ea cc cc 99 66 31 ad ff e1 a3 03 b6 47 85 76 bd 0b
	Encrypted data: sym alg is specified in pub-key encrypted session key (56 bytes)
		e7 2d 2f b1 f1 0f c3 ce 55 5d b2 8a 4b e8 4f 43 15 6e 7d 90 90 53 6a 9a e3 aa 1c 68 d6 d3 fc 6a 4e 79 a8 e7 b1 a5 87 ea cc cc 99 66 31 ad ff e1 a3 03 b6 47 85 76 bd 0b
`
	tag09Result1c = `Symmetrically Encrypted Data Packet (tag 9) (56 bytes)
	e7 2d 2f b1 f1 0f c3 ce 55 5d b2 8a 4b e8 4f 43 15 6e 7d 90 90 53 6a 9a e3 aa 1c 68 d6 d3 fc 6a 4e 79 a8 e7 b1 a5 87 ea cc cc 99 66 31 ad ff e1 a3 03 b6 47 85 76 bd 0b
	Encrypted data: sym alg is IDEA, simple string-to-key (56 bytes)
		e7 2d 2f b1 f1 0f c3 ce 55 5d b2 8a 4b e8 4f 43 15 6e 7d 90 90 53 6a 9a e3 aa 1c 68 d6 d3 fc 6a 4e 79 a8 e7 b1 a5 87 ea cc cc 99 66 31 ad ff e1 a3 03 b6 47 85 76 bd 0b
`
)

func TestTag09(t *testing.T) {
	testCases := []struct {
		tag     uint8
		content []byte
		cxt0    context.SymAlgMode
		cxt     context.SymAlgMode
		res     string
	}{
		{tag: 9, content: tag09Body1, cxt0: context.ModeSymEnc, cxt: context.ModeNotSpecified, res: tag09Result1a},
		{tag: 9, content: tag09Body1, cxt0: context.ModePubEnc, cxt: context.ModeNotSpecified, res: tag09Result1b},
		{tag: 9, content: tag09Body1, cxt0: context.ModeNotSpecified, cxt: context.ModeNotSpecified, res: tag09Result1c},
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
		switch tc.cxt0 {
		case context.ModeSymEnc:
			cxt.SetAlgSymEnc()
		case context.ModePubEnc:
			cxt.SetAlgPubEnc()
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
