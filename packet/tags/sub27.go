package tags

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//sub27 class for Key Flags Sub-packet
type sub27 subInfo

//newSub27 return sub27 instance
func newSub27(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub27{cxt: cxt, subID: subID, reader: reader.New(body)}
}

// Parse parsing Key Flags Sub-packet
func (s *sub27) Parse() (*info.Item, error) {
	rootInfo := s.subID.ToItem(s.reader, s.cxt.Debug())
	flag, err := s.reader.ReadByte()
	if err != nil {
		return nil, err
	}
	rootInfo.Add(values.Flag2Item(flag&0x01, "This key may be used to certify other keys."))
	rootInfo.Add(values.Flag2Item(flag&0x02, "This key may be used to sign data."))
	rootInfo.Add(values.Flag2Item(flag&0x04, "This key may be used to encrypt communications."))
	rootInfo.Add(values.Flag2Item(flag&0x08, "This key may be used to encrypt storage."))
	rootInfo.Add(values.Flag2Item(flag&0x10, "The private component of this key may have been split by a secret-sharing mechanism."))
	rootInfo.Add(values.Flag2Item(flag&0x20, "This key may be used for authentication."))
	rootInfo.Add(values.Flag2Item(flag&0x40, fmt.Sprintf("Unknown flag1(%#02x)", flag&0x40)))
	rootInfo.Add(values.Flag2Item(flag&0x80, "The private component of this key may be in the possession of more than one person."))
	if s.reader.Rest() > 0 {
		flags, _ := s.reader.Read2EOF()
		for i, flag := range flags {
			rootInfo.Add(values.Flag2Item(flag, fmt.Sprintf("Unknown flag%d(%#02x)", i+2, flag)))
		}
	}
	return rootInfo, nil
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
