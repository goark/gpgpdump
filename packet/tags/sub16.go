package tags

import (
	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//sub16 class for Issuer Sub-packet
type sub16 struct {
	subInfo
}

//newSub16 return sub16 instance
func newSub16(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub16{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Issuer Sub-packet
func (s *sub16) Parse() (*info.Item, error) {
	rootInfo := s.ToItem()
	keyid, err := s.reader.ReadBytes(8)
	if err != nil {
		return rootInfo, errs.Wrap(err, "illegal keyid")
	}
	issuer := values.NewKeyID(keyid).ToItem()
	issuer.Name = rootInfo.Name
	return issuer, nil
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
