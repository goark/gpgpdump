package tags

import (
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

// subInfo class as Sub-packet result.
type subInfo struct {
	cxt    *context.Context
	subID  values.SuboacketID
	reader *reader.Reader
}

// ToItem returns result.Item instance
func (s *subInfo) ToItem() *result.Item {
	return s.subID.ToItem(s.reader, s.cxt.Debug())
}

// Subs is parsing interface
type Subs interface {
	Parse() (*result.Item, error)
}

// NewSubpacket is function value of parsing Sub-packet
type NewSubpacket func(*context.Context, values.SuboacketID, []byte) Subs

// SubFuncMap is type of NewPacket function list.
type SubFuncMap map[int]NewSubpacket

// Get returns NewSubpacket function.
func (fm SubFuncMap) Get(i int, defFunc NewSubpacket) NewSubpacket {
	if f, ok := fm[i]; ok {
		return f
	}
	return defFunc
}

var newFunctionsSub02 = SubFuncMap{
	2:  newSub02, //Signature Creation Time
	3:  newSub03, //Signature Expiration Time
	4:  newSub04, //Exportable Certification
	5:  newSub05, //Trust Signature
	6:  newSub06, //Regular Expression
	7:  newSub07, //Revocable
	9:  newSub09, //Key Expiration Time
	10: newSub10, //Placeholder for backward compatibility
	11: newSub11, //Preferred Symmetric Algorithms
	12: newSub12, //Revocation Key
	16: newSub16, //Issuer
	20: newSub20, //Notation Data
	21: newSub21, //Preferred Hash Algorithms
	22: newSub22, //Preferred Compression Algorithms
	23: newSub23, //Key Server Preferences
	24: newSub24, //Preferred Key Server
	25: newSub25, //Primary User ID
	26: newSub26, //Policy URI
	27: newSub27, //Key Flags
	28: newSub28, //Signer's User ID
	29: newSub29, //Reason for Revocation
	30: newSub30, //Features
	31: newSub31, //Signature Target
	// 32: newSub32, //Embedded Signature (with recursive call)
	33: newSub33, //Issuer Fingerprint
	34: newSub34, //Preferred AEAD Algorithms
	35: newSub35, //Intended Recipient Fingerprint
	37: newSub37, //Attested Certifications
	// 38: newSub38, //Key Block (with recursive call)
	39: newSub39, //Preferred AEAD Ciphersuites
}

var newFunctionsSub17 = SubFuncMap{
	1: newSub01, //Image Attribute
}

// NewSubs returns Tags instance for pasing
func NewSubs(cxt *context.Context, osp *packet.OpaqueSubpacket, tagID values.TagID) Subs {
	st := osp.SubType & 0x7f
	if tagID == 2 {
		switch st {
		case 32:
			// recursive call in sub32.Parse()
			return newSub32(cxt, values.SuboacketID(osp.SubType), osp.Contents)
		case 38:
			// recursive call in sub38.Parse()
			return newSub38(cxt, values.SuboacketID(osp.SubType), osp.Contents)
		default:
			return newFunctionsSub02.Get(int(st), newSubReserved)(cxt, values.SuboacketID(osp.SubType), osp.Contents)
		}
	} else if tagID == 17 {
		return newFunctionsSub17.Get(int(st), newSubReserved)(cxt, values.SuboacketID(osp.SubType), osp.Contents)
	}
	return nil
}

/* Copyright 2016-2019 Spiegel
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
