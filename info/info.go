package info

import (
	"bytes"
	"encoding/json"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
)

//Info is information class for OpenPGP packets
type Info struct {
	Packets []*Item `toml:"Packet,omitempty" json:"Packet,omitempty"`
}

//NewInfo returns Info instance
func NewInfo() *Info {
	return &Info{}
}

//Add add item in Packets.
func (i *Info) Add(a *Item) {
	if a != nil && i != nil {
		i.Packets = append(i.Packets, a)
	}
}

//TOML returns TOML format string
func (i *Info) TOML() (string, error) {
	if i == nil {
		return "", nil
	}
	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(i); err != nil {
		return "", errors.Wrap(err, "error by TOML() function")
	}
	return buf.String(), nil
}

//JSON returns JSON format string
func (i *Info) JSON() (string, error) {
	if i == nil {
		return "", nil
	}
	j, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return "", errors.Wrap(err, "error by JSON() function")
	}
	return string(j), nil
}

//Item is information item class
type Item struct {
	Name  string  `toml:"name" json:"name"`
	Value string  `toml:"value,omitempty" json:"value,omitempty"`
	Dump  string  `toml:"dump,omitempty" json:"dump,omitempty"`
	Note  string  `toml:"note,omitempty" json:"note,omitempty"`
	Items []*Item `toml:"Item,omitempty" json:"Item,omitempty"`
}

//ItemOpt is self-referential function for functional options pattern
type ItemOpt func(*Item)

// NewItem returns a new Item instance
func NewItem(opts ...ItemOpt) *Item {
	i := &Item{}
	i.optins(opts...)
	return i
}
func (i *Item) optins(opts ...ItemOpt) {
	for _, opt := range opts {
		opt(i)
	}
}

//Add add sub-item in item.
func (i *Item) Add(a *Item) {
	if a != nil && i != nil {
		i.Items = append(i.Items, a)
	}
}

//Name returns closure as type ItemOpt
func Name(name string) ItemOpt {
	return func(i *Item) {
		i.Name = name
	}
}

//Value returns closure as type ItemOpt
func Value(value string) ItemOpt {
	return func(i *Item) {
		i.Value = value
	}
}

//DumpStr returns closure as type ItemOpt
func DumpStr(str string) ItemOpt {
	return func(i *Item) {
		i.Dump = str
	}
}

//Note returns closure as type ItemOpt
func Note(note string) ItemOpt {
	return func(i *Item) {
		i.Note = note
	}
}

/* Copyright 2016,2017 Spiegel
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
