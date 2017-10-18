package info

import (
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	//start test
	code := m.Run()

	//termination
	os.Exit(code)
}

func TestTOMLNull(t *testing.T) {
	info := (*Info)(nil)
	info.Add(nil)
	res, err := info.TOML()
	if err != nil {
		t.Errorf("TOML() err = %v, want nil.", err)
	}
	if res != "" {
		t.Errorf("TOML() = %v, want nil.", res)
	}
}

func TestTOMLEmpty(t *testing.T) {
	info := NewInfo()
	res, err := info.TOML()
	if err != nil {
		t.Errorf("TOML() err = %v, want nil.", err)
	}
	if res != "" {
		t.Errorf("TOML() = %v, want nil.", res)
	}
}

func TestTOML(t *testing.T) {
	norm := `
[[Packet]]
  name = "name1"
  value = "value1"
  dump = "00 01 02"
  note = "note1"

  [[Packet.Item]]
    name = "name2"
    dump = "03 04 05"
    note = "note2"
`
	output := strings.Trim(norm, " \t\n\r") + "\n"

	info := NewInfo()
	item1 := NewItem(
		Name("name1"),
		Value("value1"),
		Note("note1"),
		DumpStr("00 01 02"),
	)
	item2 := NewItem(
		Name("name2"),
		Note("note2"),
		DumpStr("03 04 05"),
	)
	item1.Add(item2)
	item1.Add(nil) //abnormal
	info.Add(item1)
	info.Add(nil) //abnormal
	toml, err := info.TOML()
	if err != nil {
		t.Errorf("MarshalTOML() = \"%v\"want nil.", err)
	}
	if toml != output {
		t.Errorf("TOML output = \n%s\n want \n%s\n", toml, output)
	}
}

func TestJSONNull(t *testing.T) {
	info := (*Info)(nil)
	info.Add(nil)
	res, err := info.JSON()
	if err != nil {
		t.Errorf("TOML() err = %v, want nil.", err)
	}
	if res != "" {
		t.Errorf("TOML() = %v, want nil.", res)
	}
}

func TestJSONEmpty(t *testing.T) {
	info := NewInfo()
	res, err := info.JSON()
	if err != nil {
		t.Errorf("TOML() err = %v, want nil.", err)
	}
	if res != "{}" {
		t.Errorf("TOML() = %v, want {}.", res)
	}

}

func TestJSON(t *testing.T) {
	norm := `
{
  "Packet": [
    {
      "name": "name1",
      "value": "value1",
      "dump": "00 01 02",
      "note": "note1",
      "Item": [
        {
          "name": "name2",
          "dump": "03 04 05",
          "note": "note2"
        }
      ]
    }
  ]
}
`
	output := strings.Trim(norm, " \t\n\r")

	info := NewInfo()
	item1 := NewItem(
		Name("name1"),
		Value("value1"),
		Note("note1"),
		DumpStr("00 01 02"),
	)
	item2 := NewItem(
		Name("name2"),
		Note("note2"),
		DumpStr("03 04 05"),
	)
	item1.Add(item2)
	info.Add(item1)
	json, err := info.JSON()
	if err != nil {
		t.Errorf("MarshalTOML() = \"%v\"want nil.", err)
	}
	if json != output {
		t.Errorf("TOML output = \n%s\n want \n%s\n", json, output)
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
