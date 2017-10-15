package packet

import (
	"bytes"
	"encoding/json"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
)

//Info is information class for OpenPGP packets
type Info struct {
	Packets []*Item `toml:"packets,omitempty" json:"packets,omitempty"`
}

//MarshalTOML returns TOML format string
func (i *Info) MarshalTOML() ([]byte, error) {
	if i == nil {
		return nil, nil
	}
	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(i); err != nil {
		return nil, errors.Wrap(err, "marshaling error by MarshalTOML() function")
	}
	return buf.Bytes(), nil
}

//MarshalJSON returns JSON format string
func (i *Info) MarshalJSON() ([]byte, error) {
	if i == nil {
		return nil, nil
	}
	buf, err := json.MarshalIndent(*i, "", "  ")
	if err != nil {
		return nil, errors.Wrap(err, "marshaling error by MarshalJSON() function")
	}
	return buf, nil
}

//Item is information item class
type Item struct {
	Name  string  `toml:"name" json:"name"`
	Value string  `toml:"value,omitempty" json:"value,omitempty"`
	Dump  string  `toml:"dump,omitempty" json:"dump,omitempty"`
	Note  string  `toml:"note,omitempty" json:"note,omitempty"`
	Item  []*Item `toml:"Item,omitempty" json:"Item,omitempty"`
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
