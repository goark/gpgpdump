package tags

import (
	"strconv"

	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

//sub35 class for Intended Recipient Fingerprint Sub-packet
type sub35 struct {
	subInfo
}

//newSub35 return sub35 instance
func newSub35(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub35{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Intended Recipient Fingerprint Sub-packet
func (s *sub35) Parse() (*result.Item, error) {
	rootInfo := s.ToItem()
	ver, err := s.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal version", errs.WithCause(err))
	}
	itm := result.NewItem(
		result.Name("Version"),
		result.Value(strconv.Itoa(int(ver))),
	)
	switch ver {
	case 4:
		itm.Note = "need 20 octets length"
	case 5:
		itm.Note = "need 32 octets length"
	default:
		itm.Note = values.Unknown
	}
	rootInfo.Add(itm)
	rootInfo.Add(values.RawData(s.reader, "Fingerprint", true))
	return rootInfo, nil
}

/* Copyright 2019,2020 Spiegel
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
