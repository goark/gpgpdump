package items

import (
	"bytes"
	"encoding/json"

	"github.com/BurntSushi/toml"
)

//Packets - OpenPGP packets
type Packets struct {
	Packet []*Item
}

//NewPackets returns NewPackets instance
func NewPackets() *Packets {
	return &Packets{}
}

//MarshalTOML returns TOML format string
func (p *Packets) MarshalTOML() (string, error) {
	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(p); err != nil {
		return "", err
	}
	return buf.String(), nil
}

//MarshalJSON returns JSON format string
func (p *Packets) MarshalJSON() (string, error) {
	buf, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

//AddPacket add item in Packets.
func (p *Packets) AddPacket(a *Item) {
	p.Packet = append(p.Packet, a)
}

//Item - item in Packets
type Item struct {
	Name  string  `toml:"name" json:"name"`
	Value string  `toml:"value,omitempty" json:"value,omitempty"`
	Dump  string  `toml:"dump,omitempty" json:"dump,omitempty"`
	Note  string  `toml:"note,omitempty" json:"note,omitempty"`
	Item  []*Item `toml:"Item,omitempty" json:"Item,omitempty"`
}

//NewItem returns Item instance
func NewItem(name, value, note, dump string) *Item {
	return &Item{Name: name, Value: value, Note: note, Dump: dump}
}

//NewItemDump returns Item instance for dump
func NewItemDump(name, dump, note string) *Item {
	return &Item{Name: name, Dump: dump, Note: note}
}

//AddSub add sub-item in item.
func (i *Item) AddSub(a *Item) {
	i.Item = append(i.Item, a)
}
