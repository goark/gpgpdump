package tags

import (
	"fmt"

	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

//sub12 class for Revocation Key Sub-packet
type sub12 struct {
	subInfo
}

//newSub12 return sub12 instance
func newSub12(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub12{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Revocation Key Sub-packet
func (s *sub12) Parse() (*result.Item, error) {
	rootInfo := s.ToItem()
	class, err := s.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal Revocation class", errs.WithCause(err))
	}
	itm := result.NewItem(
		result.Name("Class"),
		result.DumpStr(fmt.Sprintf("%02x", class)),
	)
	if (class & 0x80) != 0x00 {
		switch true {
		case (class & 0x40) != 0x00:
			itm.Value = "Sensitive"
		default:
			itm.Value = "Normal"
		}
	} else {
		itm.Value = "Unknown"
	}
	rootInfo.Add(itm)
	pubid, err := s.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(values.PubID(pubid).ToItem(s.cxt.Debug()))
	rootInfo.Add(values.RawData(s.reader, "Fingerprint", true))

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
