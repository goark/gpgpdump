package values

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
)

func TestDump(t *testing.T) {
	var data = []byte{0x01, 0x02, 0x03, 0x04}
	will := "01 02 03 04"

	res := DumpBytes(data, true).String()
	if res != will {
		t.Errorf("DumpBytes( = \"%s\", want \"%s\".", res, will)
	}
}

func TestDumpMask(t *testing.T) {
	var data = []byte{0x01, 0x02, 0x03, 0x04}
	//will := "..."
	will := ""
	res := Dump(reader.New(data), false).String()
	if res != will {
		t.Errorf("Dump = \"%s\", want \"%s\".", res, will)
	}
}

func TestDumpByte(t *testing.T) {
	str := DumpByteString(0x12, true)
	if str != "12" {
		t.Errorf("DumpByteString = \"%s\", want \"12\".", str)
	}
}

func TestDumpByteMask(t *testing.T) {
	str := DumpByteString(0x12, false)
	if DumpByteString(0x12, false) != "" {
		t.Errorf("DumpByteString = \"%s\", want \"\".", str)
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
