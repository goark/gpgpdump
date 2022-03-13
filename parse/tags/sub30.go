package tags

import (
	"fmt"

	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

//sub30 class for Features Sub-packet
type sub30 struct {
	subInfo
}

//newSub30 return sub30 instance
func newSub30(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub30{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Features Sub-packet
func (s *sub30) Parse() (*result.Item, error) {
	rootInfo := s.ToItem()
	flag, err := s.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal flag", errs.WithCause(err))
	}
	rootInfo.Add(values.Flag2Item(flag&0x01, "Modification Detection (packets 18 and 19)"))
	rootInfo.Add(values.Flag2Item(flag&0x02, "AEAD Encrypted Data (packet 20)"))
	rootInfo.Add(values.Flag2Item(flag&0x04, "Reserved"))
	rootInfo.Add(values.Flag2Item(flag&0xf8, fmt.Sprintf("Unknown flag1(%#02x)", flag&0xf8)))
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
