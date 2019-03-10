package tags

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//sub29 class for Reason for Revocation Sub-packet
type sub29 struct {
	subInfo
}

var reasonNames = values.Msgs{
	0:  "No reason specified (key revocations or cert revocations)",
	1:  "Key is superseded (key revocations)",
	2:  "Key material has been compromised (key revocations)",
	3:  "Key is retired and no longer used (key revocations)",
	32: "User ID information is no longer valid (cert revocations)",
}

//newSub29 return sub29 instance
func newSub29(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub29{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Reason for Revocation Sub-packet
func (s *sub29) Parse() (*info.Item, error) {
	rootInfo := s.ToItem()
	code, err := s.reader.ReadByte()
	var name string
	if err != nil {
		return rootInfo, errs.Wrapf(err, "illegal Reason code in parsing sub packet %d", int(s.subID))
	}
	if 100 <= code && code <= 110 {
		name = "(Private Use)"
	} else {
		name = reasonNames.Get(int(code), "Unknown reason")
	}
	rootInfo.Value = fmt.Sprintf("%s (%d)", name, code)
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
