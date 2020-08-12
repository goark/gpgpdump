package tags

import (
	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//sub04 class for Exportable Certification Sub-packet
type sub04 struct {
	subInfo
}

//newSub04 return sub04 instance
func newSub04(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub04{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Exportable Certification Sub-packet
func (s *sub04) Parse() (*info.Item, error) {
	rootInfo := s.ToItem()
	b, err := s.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal Exportable Certification", errs.WithCause(err))
	}
	if b == 0x00 {
		rootInfo.Value = "Not exportable"
	} else {
		rootInfo.Value = "Exportable"
	}
	rootInfo.Dump = values.Dump(s.reader, true).String()
	return rootInfo, nil
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
