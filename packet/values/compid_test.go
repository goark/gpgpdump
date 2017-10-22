package values

import "testing"

var testCompIDNames = []string{
	"Uncompressed (comp 0)",
	"ZIP (comp 1)",
	"ZLIB (comp 2)",
	"BZip2 (comp 3)",
	"Unknown (comp 4)",
}

func TestCompID(t *testing.T) {
	for tag := 0; tag <= 4; tag++ {
		i := CompID(tag).ToItem()
		if i.Name != "Compression Algorithm" {
			t.Errorf("CompID.Name = \"%s\", want \"Compression Algorithm\".", i.Name)
		}
		if i.Value != testCompIDNames[tag] {
			t.Errorf("CompID.Value = \"%s\", want \"%s\".", i.Value, testCompIDNames[tag])
		}
		if i.Note != "" {
			t.Errorf("CompID.Note = \"%s\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("CompID.Dump = \"%s\", want \"\".", i.Dump)
		}
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
