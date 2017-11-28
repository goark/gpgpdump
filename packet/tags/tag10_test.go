package tags

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/options"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"

	openpgp "golang.org/x/crypto/openpgp/packet"
)

var (
	tag10Body = []byte{0x50, 0x47, 0x50}
)

const (
	tag10Result = `Marker Packet (Obsolete Literal Packet) (tag 10) (3 bytes)
	50 47 50
	Literal data (3 bytes)
		50 47 50
`
)

func TestTag10(t *testing.T) {
	op := &openpgp.OpaquePacket{Tag: 10, Contents: tag10Body}
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
	if str != tag10Result {
		t.Errorf("Tag.String = \"%s\", want \"%s\".", str, tag10Result)
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
