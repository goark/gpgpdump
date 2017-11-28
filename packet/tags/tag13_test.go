package tags

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/options"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"

	openpgp "golang.org/x/crypto/openpgp/packet"
)

var (
	tag13Body1 = []byte{0x4a, 0x6f, 0x68, 0x6e, 0x20, 0x44, 0x6f, 0x65, 0x20, 0x28, 0x66, 0x6f, 0x72, 0x45, 0x43, 0x43, 0x29, 0x20, 0x3c, 0x6a, 0x6f, 0x68, 0x6e, 0x40, 0x65, 0x78, 0x61, 0x6d, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x3e}
)

const (
	tag13Result1 = `User ID Packet (tag 13) (35 bytes)
	4a 6f 68 6e 20 44 6f 65 20 28 66 6f 72 45 43 43 29 20 3c 6a 6f 68 6e 40 65 78 61 6d 6c 65 2e 63 6f 6d 3e
	User ID: John Doe (forECC) <john@examle.com>
		4a 6f 68 6e 20 44 6f 65 20 28 66 6f 72 45 43 43 29 20 3c 6a 6f 68 6e 40 65 78 61 6d 6c 65 2e 63 6f 6d 3e
`
)

func TestTag13(t *testing.T) {
	op := &openpgp.OpaquePacket{Tag: 13, Contents: tag13Body1}
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
	if cxt.AlgMode() != context.ModeNotSpecified {
		t.Errorf("Options.Mode = %v, want \"%v\".", cxt.AlgMode(), context.ModeNotSpecified)
	}
	str := i.String()
	if str != tag13Result1 {
		t.Errorf("Tag.String = \"%s\", want \"%s\".", str, tag13Result1)
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
