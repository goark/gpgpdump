package tags

import (
	"fmt"

	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

//sub27 class for Key Flags Sub-packet
type sub27 struct {
	subInfo
}

//newSub27 return sub27 instance
func newSub27(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub27{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Key Flags Sub-packet
func (s *sub27) Parse() (*result.Item, error) {
	rootInfo := s.ToItem()
	//First octet
	flag, err := s.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal flag", errs.WithCause(err))
	}
	rootInfo.Add(values.Flag2Item(flag&0x01, "This key may be used to certify other keys."))
	rootInfo.Add(values.Flag2Item(flag&0x02, "This key may be used to sign data."))
	rootInfo.Add(values.Flag2Item(flag&0x04, "This key may be used to encrypt communications."))
	rootInfo.Add(values.Flag2Item(flag&0x08, "This key may be used to encrypt storage."))
	rootInfo.Add(values.Flag2Item(flag&0x10, "The private component of this key may have been split by a secret-sharing mechanism."))
	rootInfo.Add(values.Flag2Item(flag&0x20, "This key may be used for authentication."))
	rootInfo.Add(values.Flag2Item(flag&0x40, fmt.Sprintf("Unknown flag1(%#02x)", flag&0x40)))
	rootInfo.Add(values.Flag2Item(flag&0x80, "The private component of this key may be in the possession of more than one person."))

	//second octet
	if s.reader.Rest() > 0 {
		flag, err := s.reader.ReadByte()
		if err != nil {
			return rootInfo, errs.New("illegal flag", errs.WithCause(err))
		}
		rootInfo.Add(values.Flag2Item(flag&0x04, "Reserved (ADSK)."))
		rootInfo.Add(values.Flag2Item(flag&0x08, "Reserved (timestamping)."))
		rootInfo.Add(values.Flag2Item(flag&0xf3, fmt.Sprintf("Unknown flag2(%#02x)", flag&0xf3)))
	}

	//other flags
	if s.reader.Rest() > 0 {
		flags, _ := s.reader.Read2EOF()
		for i, flag := range flags {
			rootInfo.Add(values.Flag2Item(flag, fmt.Sprintf("Unknown flag%d(%#02x)", i+2, flag)))
		}
	}
	return rootInfo, nil
}

/* Copyright 2016-2021 Spiegel
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
