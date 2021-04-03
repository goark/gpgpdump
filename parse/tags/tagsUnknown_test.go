package tags

import (
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
)

func TestTagUnknown(t *testing.T) {
	op := &packet.OpaquePacket{Tag: 99, Contents: []byte{0x01, 0x02, 0x03, 0x04}}
	cxt := context.New(
		context.Set(context.DEBUG, true),
		context.Set(context.GDUMP, true),
		context.Set(context.INTEGER, true),
		context.Set(context.LITERAL, true),
		context.Set(context.MARKER, true),
		context.Set(context.PRIVATE, true),
		context.Set(context.UTC, true),
	)
	itemStr := `Unknown (tag 99) (4 bytes)
	01 02 03 04
`
	i, err := NewTag(op, cxt).Parse()
	if err != nil {
		t.Errorf("NewTag() = %v, want nil error.", err)
		return
	}
	if cxt.AlgMode() != context.ModeNotSpecified {
		t.Errorf("Options.Mode = %v, want \"%v\".", cxt.AlgMode(), context.ModeNotSpecified)
	}
	str := i.String()
	if str != itemStr {
		t.Errorf("Tag.String = \"%s\", want \"%s\".", str, itemStr)
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
