package tags

import (
	"strconv"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
)

//sub05 class for Trust Signature Sub-packet
type sub05 struct {
	subInfo
}

//newSub05 return sub05 instance
func newSub05(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub05{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Trust Signature Sub-packet
func (s *sub05) Parse() (*result.Item, error) {
	rootInfo := s.ToItem()
	b, err := s.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal Level", errs.WithCause(err))
	}
	rootInfo.Add(result.NewItem(
		result.Name("Level"),
		result.Value(strconv.Itoa(int(b))),
	))
	b, err = s.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal Trust amount", errs.WithCause(err))
	}
	rootInfo.Add(result.NewItem(
		result.Name("Trust amount"),
		result.Value(strconv.Itoa(int(b))),
	))
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
