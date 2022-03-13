package tags

import (
	"fmt"

	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

//sub23 class for Key Server Preferences Sub-packet
type sub23 struct {
	subInfo
}

//newSub23 return sub23 instance
func newSub23(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub23{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Key Server Preferences Sub-packet
func (s *sub23) Parse() (*result.Item, error) {
	rootInfo := s.ToItem()
	flag, err := s.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal flag", errs.WithCause(err))
	}
	rootInfo.Add(values.Flag2Item(flag&0x80, "No-modify"))
	rootInfo.Add(values.Flag2Item(flag&0x7f, fmt.Sprintf("Unknown flag1(%#02x)", flag&0x7f)))
	if s.reader.Rest() > 0 {
		flags, _ := s.reader.Read2EOF()
		for i, flag := range flags {
			rootInfo.Add(values.Flag2Item(flag, fmt.Sprintf("Unknown flag%d(%#02x)", i+2, flag)))
		}
	}
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
