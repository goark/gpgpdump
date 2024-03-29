package tags

import (
	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

//sub02 class for Signature Creation Time Sub-packet
type sub02 struct {
	subInfo
}

//newSub02 return sub02 instance
func newSub02(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub02{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Signature Creation Time Sub-packet
func (s *sub02) Parse() (*result.Item, error) {
	rootInfo := s.ToItem()
	tm, err := values.NewDateTime(s.reader, s.cxt.UTC())
	if err != nil {
		return rootInfo, errs.New("illegal Signature Creation Time", errs.WithCause(err))
	}
	sigTime := values.SigTimeItem(tm, s.cxt.Debug())
	sigTime.Name = rootInfo.Name
	s.cxt.SigCreationTime = tm
	return sigTime, nil
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
