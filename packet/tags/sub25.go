package tags

import (
	"github.com/spiegel-im-spiegel/gpgpdump/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//sub25 class for Primary User ID Sub-packet
type sub25 struct {
	subInfo
}

//newSub25 return sub25 instance
func newSub25(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub25{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Primary User ID Sub-packet
func (s *sub25) Parse() (*info.Item, error) {
	rootInfo := s.ToItem()
	b, err := s.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.Wrapf(err, "illegal uid in parsing sub packet %d", int(s.subID))
	}
	if b == 0x00 {
		rootInfo.Value = "Not primary"
	} else {
		rootInfo.Value = "Primary"
	}
	return rootInfo, nil
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
