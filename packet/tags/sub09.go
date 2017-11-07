package tags

import (
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//sub09 class for Key Expiration Time Sub-packet
type sub09 subInfo

//newSub09 return sub09 instance
func newSub09(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub09{cxt: cxt, subID: subID, reader: reader.NewReader(body)}
}

// Parse parsing Key Expiration Time Sub-packet
func (s *sub09) Parse() (*info.Item, error) {
	exp, _ := values.NewExpire(s.reader, s.cxt.KeyCreationTime)
	s.cxt.KeyCreationTime = nil
	return exp.ToItem(s.subID.ToItem(s.reader, s.cxt.Debug()).Name, s.cxt.Debug()), nil
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
