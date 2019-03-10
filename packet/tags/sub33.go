package tags

import (
	"strconv"

	"github.com/spiegel-im-spiegel/gpgpdump/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//sub33 class for Issuer Fingerprint Sub-packet
type sub33 struct {
	subInfo
}

//newSub33 return sub33 instance
func newSub33(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub33{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Issuer Fingerprint Sub-packet
func (s *sub33) Parse() (*info.Item, error) {
	rootInfo := s.ToItem()
	ver, err := s.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.Wrapf(err, "illegal version in parsing sub packet %d", int(s.subID))
	}
	itm := info.NewItem(
		info.Name("Version"),
		info.Value(strconv.Itoa(int(ver))),
	)
	switch ver {
	case 4:
		itm.Note = "need 20 octets length"
	case 5:
		itm.Note = "need 25 octets length"
	default:
		itm.Note = values.Unknown
	}
	rootInfo.Add(itm)
	rootInfo.Add(values.RawData(s.reader, "Fingerprint", true))
	return rootInfo, nil
}

/* Copyright 2017-2019 Spiegel
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
