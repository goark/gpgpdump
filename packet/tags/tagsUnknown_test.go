package tags

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/options"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"

	openpgp "golang.org/x/crypto/openpgp/packet"
)

func TestTagUnknown(t *testing.T) {
	op := &openpgp.OpaquePacket{Tag: 99, Contents: []byte{0x01, 0x02, 0x03, 0x04}}
	cxt := context.NewContext(options.New(
		options.Set(options.DebugOpt, true),
	))
	itemStr := `Unknown (tag 99) (4 bytes)
	01 02 03 04
`
	i, err := NewTag(op, cxt).Parse()
	if err != nil {
		t.Errorf("NewTag() = %v, want nil error.", err)
		return
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
