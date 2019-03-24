package values

import (
	"fmt"
	"testing"
)

var testAEADIDNames = []string{
	"Unknown (aead 0)",
	"EAX mode (aead 1)",
	"OCB mode <RFC7253> (aead 2)",
	"Unknown (aead 3)",
}

func TestAEADID(t *testing.T) {
	for tag := 0; tag < len(testAEADIDNames); tag++ {
		i := AEADID(tag).ToItem(false)
		if i.Name != "AEAD Algorithm" {
			t.Errorf("AEADID.Name = \"%s\", want \"AEAD Algorithm\".", i.Name)
		}
		if i.Value != testAEADIDNames[tag] {
			t.Errorf("AEADID.Value = \"%s\", want \"%s\".", i.Value, testAEADIDNames[tag])
		}
		if i.Note != "" {
			t.Errorf("AEADID.Note = \"%s\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("AEADID.Dump = \"%s\", want \"\".", i.Dump)
		}
	}
	for tag := 100; tag <= 110; tag++ {
		i := AEADID(tag).ToItem(false)
		value := fmt.Sprintf("Private/Experimental algorithm (aead %d)", tag)
		if i.Value != value {
			t.Errorf("AEADID.Value = \"%s\", want \"%s\".", i.Value, value)
		}
	}
}

/* Copyright 2019 Spiegel
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
