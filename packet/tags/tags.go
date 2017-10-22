package tags

import (
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
	openpgp "golang.org/x/crypto/openpgp/packet"
)

//tagInfo class as packet info. for all tags
type tagInfo struct {
	cxt    *context.Context
	tag    values.TagID
	reader *reader.Reader
}

//Tags parsing interface
type Tags interface {
	Parse() (*info.Item, error)
}

//NewPacket is function value of parsing Packet
type NewPacket func(*context.Context, values.TagID, []byte) Tags

//FuncMap is type of NewPacket function list.
type FuncMap map[int]NewPacket

//Get returns NewPacket function.
func (fm FuncMap) Get(i int, defFunc NewPacket) NewPacket {
	if f, ok := fm[i]; ok {
		return f
	}
	return defFunc
}

var newFunctions = FuncMap{
	1:  newTag01, //Public-Key Encrypted Session Key Packet
	2:  newTag02, //Signature Packet
	3:  newTag03, //Symmetric-Key Encrypted Session Key Packet
	4:  newTag04, //One-Pass Signature Packet
	5:  newTag05, //Secret-Key Packet
	6:  newTag06, //Public-Key Packet
	7:  newTag07, //Secret-Subkey Packet
	8:  newTag08, //Compressed Data Packet
	9:  newTag08, //Symmetrically Encrypted Data Packet
	10: newTag10, //Marker Packet (Obsolete Literal Packet)
	11: newTag11, //Literal Data Packet
	12: newTag12, //Trust Packet
	13: newTag13, //User ID Packet
	14: newTag14, //Public-Subkey Packet
	17: newTag17, //User Attribute Packet
	18: newTag18, //Sym. Encrypted Integrity Protected Data Packet
	19: newTag19, //Modification Detection Code Packet
}

//NewTag returns Tags instance for pasing
func NewTag(op *openpgp.OpaquePacket, cxt *context.Context) Tags {
	if op.Tag == 2 {
		// recursive call in tag02.Parse() -> sub32.Parse()
		return newTag02(cxt, values.TagID(op.Tag), op.Contents)
	}
	return newFunctions.Get(int(op.Tag), newTagUnknown)(cxt, values.TagID(op.Tag), op.Contents)
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
