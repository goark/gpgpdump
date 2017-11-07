package values

import (
	"fmt"
	"testing"
)

var testHashIDNames = []string{
	"Unknown (hash 0)",
	"MD5 (hash 1)",
	"SHA-1 (hash 2)",
	"RIPE-MD/160 (hash 3)",
	"Reserved (hash 4)",
	"Reserved (hash 5)",
	"Reserved (hash 6)",
	"Reserved (hash 7)",
	"SHA256 (hash 8)",
	"SHA384 (hash 9)",
	"SHA512 (hash 10)",
	"SHA224 (hash 11)",
	"Unknown (hash 12)",
}

func TestHashID(t *testing.T) {
	for tag := 0; tag <= 12; tag++ {
		i := HashID(tag).ToItem(false)
		if i.Name != "Hash Algorithm" {
			t.Errorf("HashAlg.Name = \"%s\", want \"Hash Algorithm\".", i.Name)
		}
		if i.Value != testHashIDNames[tag] {
			t.Errorf("HashAlg.Value = \"%s\", want \"%s\".", i.Value, testHashIDNames[tag])
		}
		if i.Note != "" {
			t.Errorf("HashAlg.Note = \"%s\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("HashAlg.Dump = \"%s\", want \"\".", i.Dump)
		}
	}
	for tag := 100; tag <= 110; tag++ {
		i := HashID(tag).ToItem(false)
		value := fmt.Sprintf("Private/Experimental algorithm (hash %d)", tag)
		if i.Value != value {
			t.Errorf("HashAlg.Value = \"%s\", want \"%s\".", i.Value, value)
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
