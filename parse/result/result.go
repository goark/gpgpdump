package result

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spiegel-im-spiegel/errs"
)

//Info is information class for OpenPGP packets
type Info struct {
	Packets []*Item `toml:"Packet,omitempty" json:"Packet,omitempty"`
}

//New returns Info instance
func New() *Info {
	return &Info{}
}

//Add add item in Packets.
func (i *Info) Add(a *Item) {
	if i == nil {
		return
	}
	if a != nil {
		i.Packets = append(i.Packets, a)
	}
}

//JSON returns JSON formated string
func (i *Info) JSON(indent int) (io.Reader, error) {
	if i == nil {
		return bytes.NewReader([]byte{}), nil
	}
	if indent > 0 {
		b, err := json.MarshalIndent(i, "", strings.Repeat(" ", indent))
		return bytes.NewReader(b), errs.Wrap(err)
	}
	b, err := json.Marshal(i)
	return bytes.NewReader(b), errs.Wrap(err)
}

//ToString returns string buffer
func (i *Info) ToString(indent string) *bytes.Buffer {
	buf := &bytes.Buffer{}
	if i == nil {
		return buf
	}
	if len(i.Packets) == 0 {
		return buf
	}
	for _, itm := range i.Packets {
		itm.toString(indent, 0, buf)
	}
	return buf
}

//Stringer as TOML format
func (i *Info) String() string {
	return i.ToString("\t").String()
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
	if i == nil {
		return
	}
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

func (i *Item) toString(indent string, lvl int, buf *bytes.Buffer) *bytes.Buffer {
	if i == nil || buf == nil {
		return buf
	}
	fmt.Fprintf(buf, "%s%s", strings.Repeat(indent, lvl), i.Name)
	if len(i.Value) > 0 {
		fmt.Fprintf(buf, ": %s", i.Value)
	}
	if len(i.Note) > 0 {
		fmt.Fprintf(buf, " (%s)", i.Note)
	}
	buf.WriteString("\n")
	if len(i.Dump) > 0 {
		fmt.Fprintf(buf, "%s%s\n", strings.Repeat(indent, lvl+1), i.Dump)
	}
	if len(i.Items) > 0 {
		for _, itm := range i.Items {
			itm.toString(indent, lvl+1, buf)
		}
	}
	return buf
}

func (i *Item) String() string {
	return i.toString("\t", 0, &bytes.Buffer{}).String()
}

/* Copyright 2016-2020 Spiegel
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
