package items

import (
	"strings"
	"testing"
)

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

	pckt := NewPackets()
	item1 := NewItem("name1", "value1", "note1", "00 01 02")
	item2 := NewItemDump("name2", "03 04 05", "note2")
	item1.AddSub(item2)
	pckt.AddPacket(item1)
	toml, err := pckt.MarshalTOML()
	if err != nil {
		t.Errorf("MarshalTOML() = \"%v\"want nil.", err)
	}
	if toml != output {
		t.Errorf("TOML output = \n%s\n want \n%s\n", toml, output)

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

	pckt := NewPackets()
	item1 := NewItem("name1", "value1", "note1", "00 01 02")
	item2 := NewItemDump("name2", "03 04 05", "note2")
	item1.AddSub(item2)
	pckt.AddPacket(item1)
	toml, err := pckt.MarshalJSON()
	if err != nil {
		t.Errorf("MarshalTOML() = \"%v\"want nil.", err)
	}
	if toml != output {
		t.Errorf("TOML output = \n%s\n want \n%s\n", toml, output)

	}
}
