package tags

import (
	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

//sub07 class for Revocable Sub-packet
type sub07 struct {
	subInfo
}

//newSub07 return sub07 instance
func newSub07(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub07{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Revocable Sub-packet
func (s *sub07) Parse() (*result.Item, error) {
	rootInfo := s.ToItem()
	b, err := s.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal Revocable value", errs.WithCause(err))
	}
	if b == 0x00 {
		rootInfo.Value = "Not revocable"
	} else {
		rootInfo.Value = "Revocablee"
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
