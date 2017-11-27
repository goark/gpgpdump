package values

import (
	"fmt"
	"testing"
)

var testSymIDNames = []string{
	"Plaintext or unencrypted data (sym 0)",
	"IDEA (sym 1)",
	"TripleDES (168 bit key derived from 192) (sym 2)",
	"CAST5 (128 bit key, as per) (sym 3)",
	"Blowfish (128 bit key, 16 rounds) (sym 4)",
	"Reserved (sym 5)",
	"Reserved (sym 6)",
	"AES with 128-bit key (sym 7)",
	"AES with 192-bit key (sym 8)",
	"AES with 256-bit key (sym 9)",
	"Twofish with 256-bit key (sym 10)",
	"Camellia with 128-bit key (sym 11)",
	"Camellia with 192-bit key (sym 12)",
	"Camellia with 256-bit key (sym 13)",
	"Unknown (sym 14)",
}

func TestSymID(t *testing.T) {
	for tag := 0; tag <= 14; tag++ {
		i := SymID(tag).ToItem(false)
		if i.Name != "Symmetric Algorithm" {
			t.Errorf("SymID.Name = \"%s\", want \"Symmetric Algorithm\".", i.Name)
		}
		if i.Value != testSymIDNames[tag] {
			t.Errorf("SymID.Value = \"%s\", want \"%s\".", i.Value, testSymIDNames[tag])
		}
		if i.Note != "" {
			t.Errorf("SymID.Note = \"%s\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("SymID.Dump = \"%s\", want \"\".", i.Dump)
		}
	}
	for tag := 100; tag <= 110; tag++ {
		i := SymID(tag).ToItem(false)
		value := fmt.Sprintf("Private/Experimental algorithm (sym %d)", tag)
		if i.Value != value {
			t.Errorf("SymID.Value = \"%s\", want \"%s\".", i.Value, value)
		}
	}
}

var testSymIDIVLen = []int{
	8,  //Plaintext or unencrypted data
	8,  //IDEA
	8,  //TripleDES (168 bit key derived from 192)
	8,  //CAST5
	8,  //Blowfish
	8,  //Reserved
	8,  //Reserved
	16, //AES with 128-bit key
	16, //AES with 192-bit key
	16, //AES with 256-bit key
	16, //Twofish with 256-bit key
	16, //Camellia with 128-bit key
	16, //Camellia with 192-bit key
	16, //Camellia with 256-bit key
	0,  //Unknown
}

func TestSymIDIVLen(t *testing.T) {
	for tag := 0; tag <= 14; tag++ {
		v := SymID(tag)
		if v.IVLen() != testSymIDIVLen[tag] {
			t.Errorf("SymID.IVLen(%d) = %d, want %d.", tag, v.IVLen(), testSymIDIVLen[tag])
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
