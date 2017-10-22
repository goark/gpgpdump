package values

import (
	"fmt"
	"testing"
)

var testS2kIDNames = []string{
	"Simple S2K (s2k 0)",
	"Salted S2K (s2k 1)",
	"Reserved (s2k 2)",
	"Iterated and Salted S2K (s2k 3)",
	"Unknown (s2k 4)",
}

func TestS2KID(t *testing.T) {
	for tag := 0; tag <= 4; tag++ {
		i := S2KID(tag).ToItem()
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2KID.Name = \"%s\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != testS2kIDNames[tag] {
			t.Errorf("S2KID.Value = \"%s\", want \"%s\".", i.Value, testS2kIDNames[tag])
		}
		if i.Note != "" {
			t.Errorf("S2KID.Note = \"%s\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("S2KID.Dump = \"%s\", want \"\".", i.Dump)
		}
	}
	for tag := 100; tag <= 110; tag++ {
		i := S2KID(tag).ToItem()
		value := fmt.Sprintf("Private/Experimental algorithm (s2k %d)", tag)
		if i.Value != value {
			t.Errorf("S2KID.Value = \"%s\", want \"%s\".", i.Value, value)
		}
	}
}

func TestSalt(t *testing.T) {
	salt := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	dump := "01 02 03 04 05 06 07 08"
	i := Salt(salt).ToItem(true)
	if i.Name != "Salt" {
		t.Errorf("Salt.Name = \"%s\", want \"SSalt\".", i.Name)
	}
	if i.Dump != dump {
		t.Errorf("Salt.Dump = \"%s\", want \"%s\".", i.Dump, dump)
	}
}

func TestStretch(t *testing.T) {
	i := Stretch(0xc3).ToItem()
	if i.Name != "Count" {
		t.Errorf("Stretch.Name = \"%s\", want \"Count\".", i.Name)
	}
	if i.Value != "4980736" {
		t.Errorf("Stretch.Name = \"%s\", want \"4980736\".", i.Value)
	}
	if i.Note != "coded: 0xc3" {
		t.Errorf("Stretch.Name = \"%s\", want \"coded: 0xc3\".", i.Note)
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
